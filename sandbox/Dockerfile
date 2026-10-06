# Study Room sandbox image (SPEC 9, 10, 11, 12, 16.2, 17).
#
# Built locally by `study-room build` and loaded into Docker Sandboxes as a
# template. It is never pushed or published (SPEC 4). Every pin arrives as a
# required build argument computed from lock/study-room.lock.json
# (studyroom/lock.py build_args); this file declares no defaults, so a
# missing or moved pin fails the build instead of resolving to a newer
# version. Build context: the repository root.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG NODE_VERSION
ARG NODE_SHA256
ARG NPM_TREE_SHA256
ARG LEARN_URL
ARG LEARN_COMMIT
ARG LEARN_TREE
ARG SUBAGENTS_URL
ARG SUBAGENTS_COMMIT
ARG SUBAGENTS_TREE
ARG SANDBOX_APT_PACKAGES
ARG SANDBOX_APT_CONSTRAINTS

USER root
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN for v in NODE_VERSION NODE_SHA256 NPM_TREE_SHA256 LEARN_URL LEARN_COMMIT LEARN_TREE \
             SUBAGENTS_URL SUBAGENTS_COMMIT SUBAGENTS_TREE SANDBOX_APT_PACKAGES SANDBOX_APT_CONSTRAINTS; do \
      [ -n "${!v}" ] || { echo "missing build argument $v (build with study-room build)" >&2; exit 1; }; \
    done

COPY sandbox/bin/check-apt-constraints.sh sandbox/bin/verify-checkout.sh sandbox/bin/fetch-upstream.sh sandbox/bin/tree-digest.mjs /opt/study-room/bin/

# System packages, then the lock's version constraints.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${SANDBOX_APT_PACKAGES} \
 && rm -rf /var/lib/apt/lists/* \
 && /opt/study-room/bin/check-apt-constraints.sh ${SANDBOX_APT_CONSTRAINTS}

# Pinned Node.js release, checksum-verified.
RUN curl -fsSL --retry 3 -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
 && mkdir -p /opt/study-room/node \
 && tar -xJf /tmp/node.tar.xz -C /opt/study-room/node --strip-components=1 --no-same-owner \
 && rm /tmp/node.tar.xz \
 && [ "$(/opt/study-room/node/bin/node --version)" = "v${NODE_VERSION}" ]

# Pinned npm tree: `npm ci` from the checked-in lockfile, then the whole
# installed tree is compared with the lock's digest (npm does not check
# integrity inside Pi's own shrinkwrap, so the tree digest is what pins it).
COPY sandbox/runtime/package.json sandbox/runtime/package-lock.json sandbox/runtime/.npmrc /opt/study-room/runtime/
RUN cd /opt/study-room/runtime \
 && PATH=/opt/study-room/node/bin:$PATH npm ci --no-update-notifier --cache /tmp/npm-cache \
 && rm -rf /tmp/npm-cache \
 && actual=$(/opt/study-room/node/bin/node /opt/study-room/bin/tree-digest.mjs node_modules | cut -d' ' -f1) \
 && { [ "$actual" = "$NPM_TREE_SHA256" ] || { echo "npm tree digest $actual does not match the lock ($NPM_TREE_SHA256)" >&2; exit 1; }; } \
 && ln -s runtime/node_modules /opt/study-room/node_modules \
 && chmod -R a-w /opt/study-room/runtime

# Unmodified upstream checkouts at their exact pinned commits (SPEC 10.1, 11.1).
RUN /opt/study-room/bin/fetch-upstream.sh "$LEARN_URL" "$LEARN_COMMIT" "$LEARN_TREE" /opt/study-room/upstream/learn \
 && /opt/study-room/bin/fetch-upstream.sh "$SUBAGENTS_URL" "$SUBAGENTS_COMMIT" "$SUBAGENTS_TREE" /opt/study-room/upstream/pi-interactive-subagents

# Project-owned sandbox code, tests and entry points.
COPY sandbox/lib /opt/study-room/lib
COPY sandbox/extensions /opt/study-room/extensions
COPY sandbox/tests /opt/study-room/tests
COPY sandbox/bin /opt/study-room/bin
RUN printf '%s\n' \
      "{\"node\":\"${NODE_VERSION}\",\"npm_tree_sha256\":\"${NPM_TREE_SHA256}\"," \
      "\"upstream\":{\"learn\":{\"url\":\"${LEARN_URL}\",\"commit\":\"${LEARN_COMMIT}\",\"tree\":\"${LEARN_TREE}\",\"dir\":\"/opt/study-room/upstream/learn\"}," \
      "\"pi-interactive-subagents\":{\"url\":\"${SUBAGENTS_URL}\",\"commit\":\"${SUBAGENTS_COMMIT}\",\"tree\":\"${SUBAGENTS_TREE}\",\"dir\":\"/opt/study-room/upstream/pi-interactive-subagents\"}}}" \
      > /tmp/build.json \
 && mkdir -p /opt/study-room/etc/agents \
 && /opt/study-room/node/bin/node -e 'JSON.parse(require("fs").readFileSync("/tmp/build.json","utf8"))' \
 && mv /tmp/build.json /opt/study-room/etc/build.json \
 && ln -sf /opt/study-room/bin/pi /usr/local/bin/pi \
 && ln -sf /opt/study-room/bin/study-room-entry /usr/local/bin/study-room-entry \
 && chown -R root:root /opt/study-room \
 && chmod -R a-w /opt/study-room/lib /opt/study-room/extensions /opt/study-room/tests /opt/study-room/bin \
 && chmod 0755 /opt/study-room/etc /opt/study-room/etc/agents

ENV PATH=/opt/study-room/bin:/opt/study-room/node/bin:$PATH
USER agent
WORKDIR /home/agent
