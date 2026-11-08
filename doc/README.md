# identity documentation

The [README](../README.md) says what the service is, how it fits vif and the
router, how to build and run it and where it is deployed.

- [Design](design.md): the service's decisions and why, its packages and their
  dependencies, each flow, the threats and what meets each, the deployment's
  roles, and what the scaffold leaves out.
- [API](api.md): every route, request and answer, the error form, the limits.
- [Agent notes](agent-notes.md): what working here teaches that no document
  states; read it before starting.
- [To do](todo.md): the remaining work, in order.
- [The database](../schema/README.md): provisioning the jail's PostgreSQL,
  migrating, verifying, backups.
- [deploy](../deploy/README.md): where each file lands on the node and the jail.

The decisions this service serves are vif's, in its
[authentication and session design](https://github.com/lixenwraith/vif/blob/main/doc/auth-session-design.md):
D8 to D11 and D17, §7.5, §8 under phase 5, §9.
