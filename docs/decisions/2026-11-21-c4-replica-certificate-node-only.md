# A service replica's certificate is the node's own, like a job's

*Decided 2026-11-21, by the C4 port onto main (slices 1-4).*

C4 slice 3 added `POST /v1/agent/nodes/<name>/replicas/<id>/certificate`, which signs a service
replica's identity (`spiffe://<cluster>/svc/...`) for whatever key it is given. The old C4 branch
predates B7's scopes and the 0.5.2 review, which made `/credential` and
`/runs/<job>/certificate` callable by node `<name>`'s own certificate only (and `local`): no client
certificate, `admin` included, may mint an identity for a key of its own.

Ported onto main, the replica endpoint would have fallen under the plain per-node rule and let an
`admin` client mint a replica's identity. The port resolves the conflict in favour of main's rule:
`api_scope.need_of` treats `/replicas/<id>/certificate` as `node_only`, exactly as it treats a
run's. No code, bound or default changes; the refusal is the existing 403 `ZC-E0822`.

Where: `src/api_scope.zig` (`run_certificate`, its table test), `docs/mtls.md` ("Scopes").
