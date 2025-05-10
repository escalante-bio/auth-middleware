load("@aspect_bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")

def _all_stamp_variables_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".txt")
    stamp = maybe_stamp(ctx)

    if stamp:
        files = [stamp.volatile_status_file, stamp.stable_status_file]
        ctx.actions.run_shell(
            inputs = files,
            outputs = [output],
            command = "cat " + " ".join([f.path for f in files]) + " > " + output.path,
        )
    else:
        ctx.actions.write(output, "")

    return [DefaultInfo(files = depset([output]))]

all_stamp_variables = rule(
    implementation = _all_stamp_variables_impl,
    attrs = STAMP_ATTRS,
)
