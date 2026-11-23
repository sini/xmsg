{
  pkgs,
  nixosModule,
  package,
}:
pkgs.testers.runNixOSTest {
  name = "xmsg-nixos-instances";

  nodes.machine =
    { ... }:
    {
      imports = [ nixosModule ];

      users.groups.xmsg-alpha = { };
      users.users.xmsg-alpha = {
        isSystemUser = true;
        group = "xmsg-alpha";
      };

      users.groups.xmsg-beta = { };
      users.users.xmsg-beta = {
        isSystemUser = true;
        group = "xmsg-beta";
      };

      services.xmsg.instances = {
        alpha = {
          inherit package;
          user = "xmsg-alpha";
          group = "xmsg-alpha";
        };
        beta = {
          inherit package;
          user = "xmsg-beta";
          group = "xmsg-beta";
        };
      };
    };

  testScript = ''
    xmsg_bin = "${package}/bin/xmsg"

    machine.start()
    machine.wait_for_unit("xmsg-alpha.service")
    machine.wait_for_unit("xmsg-beta.service")

    def check_dirs():
        for name in ("alpha", "beta"):
            user = f"xmsg-{name}"
            rt_stat = machine.succeed(f"stat -c '%a %U %G' /run/xmsg-{name}").strip()
            assert rt_stat == f"700 {user} {user}", f"unexpected runtimeDir stat for {name}: {rt_stat}"
            st_stat = machine.succeed(f"stat -c '%a %U %G' /var/lib/xmsg-{name}").strip()
            assert st_stat == f"700 {user} {user}", f"unexpected stateDir stat for {name}: {st_stat}"
            machine.succeed(f"test -S /run/xmsg-{name}/xmsg/http.sock")

    check_dirs()

    # No TCP listener by default (allowTcpListen = false).
    tcp_listeners = machine.succeed("ss -tlnH").strip()
    assert tcp_listeners == "", f"expected no TCP listeners by default, got: {tcp_listeners}"

    # Instance user reaches its own instance via pinned socket; other user is refused.
    for own, other in (("alpha", "beta"), ("beta", "alpha")):
        machine.succeed(
            f"runuser -u xmsg-{own} -- env XDG_RUNTIME_DIR=/run/xmsg-{own} "
            f"XMSG_HTTP_SOCK=/run/xmsg-{own}/xmsg/http.sock {xmsg_bin} list"
        )
        machine.fail(
            f"runuser -u xmsg-{other} -- env XDG_RUNTIME_DIR=/run/xmsg-{other} "
            f"XMSG_HTTP_SOCK=/run/xmsg-{own}/xmsg/http.sock {xmsg_bin} list"
        )

    # Restart is clean: no UnprovenExistingSocket, dirs remain 0700/owned, clients still work.
    machine.succeed("systemctl restart xmsg-alpha.service xmsg-beta.service")
    machine.wait_for_unit("xmsg-alpha.service")
    machine.wait_for_unit("xmsg-beta.service")

    check_dirs()

    for name in ("alpha", "beta"):
        logs = machine.succeed(f"journalctl -u xmsg-{name}.service --no-pager")
        assert "UnprovenExistingSocket" not in logs, f"UnprovenExistingSocket in {name} logs: {logs}"
        machine.succeed(
            f"runuser -u xmsg-{name} -- env XDG_RUNTIME_DIR=/run/xmsg-{name} "
            f"XMSG_HTTP_SOCK=/run/xmsg-{name}/xmsg/http.sock {xmsg_bin} list"
        )
  '';
}
