// Who the kernel kills first when the whole host runs out of memory.
//
// Every container AppCrane starts carries --oom-score-adj (docker run --help:
// "Tune host's OOM preferences (-1000 to 1000)"). The kernel's victim score is
// roughly the process's share of RAM (0-1000) plus this adjustment, and children
// inherit it from the container's init, so every process in the container gets
// it. A positive value needs no privilege; Docker refuses a negative one from an
// unprivileged daemon user, which is why nothing here is negative.
//
//   app  +500  app containers (production and sandbox), the coder, Ask, helpers,
//              catalogue apps: the first to go. A killed app restarts
//              (--restart=on-failure:2) and a redeploy brings it back.
//   db   +300  managed database servers: still well ahead of the host, but behind
//              the apps, because a killed database takes every app on it down
//              with it and recovers through crash recovery, not a clean restart.
//
// The host side lowers itself: the systemd unit install.sh writes sets
// OOMScoreAdjust=-500 for AppCrane, and oomSelfProtect.js applies the same at
// startup for an install whose unit predates that line. sshd and the security
// agent are the operator's units to change (see the README's host hardening note).

export const OOM_SCORE_ADJ = Object.freeze({ app: 500, db: 300 });

export const OOM_APP_FLAG = `--oom-score-adj=${OOM_SCORE_ADJ.app}`;
export const OOM_DB_FLAG = `--oom-score-adj=${OOM_SCORE_ADJ.db}`;
