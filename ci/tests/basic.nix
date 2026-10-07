{ lib, inputs, ... }:
{
  flake.tests.basic = {
    test-meta-description = {
      expr = inputs.xmsg.packages.x86_64-linux.default.meta.description;
      expected = "Fast, lightweight local HTTP bridge into live agent sessions";
    };
  };
}
