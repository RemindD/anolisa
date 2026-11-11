forbid(principal, action == SecCore::Action::"file.write", resource)
when {
  ["/run/asc-demo/work/keyfile",
   "/run/asc-demo/work/keyfile.alias"].contains(resource.path) &&
  [SecCore::WriteOperation::"write",
   SecCore::WriteOperation::"delete"].contains(context.input.operation)
};
