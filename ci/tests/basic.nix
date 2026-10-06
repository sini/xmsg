{ lib, ... }:
{
  flake.tests.basic = {
    test-sanity = {
      expr = true;
      expected = true;
    };
  };
}
