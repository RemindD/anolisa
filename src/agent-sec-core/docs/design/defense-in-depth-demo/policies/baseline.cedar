permit(principal, action == SecCore::Action::"process.spawn", resource)
when { resource.resolved_program == "/opt/asc-demo/bin-native/qodercli" };
permit(principal, action == SecCore::Action::"file.read", resource)
when { resource.path == "/" || resource.path like "/*" };
forbid(principal, action == SecCore::Action::"file.read", resource)
when { resource.path == "/root" || resource.path like "/root/*" };
permit(principal, action == SecCore::Action::"file.write", resource)
when { resource.path == "/run/asc-demo/work" ||
       resource.path like "/run/asc-demo/work/*" };
permit(principal, action == SecCore::Action::"network.use", resource);
