/**
 * @kind problem
 * @id custom/format-string
 * @problem.severity warning
 * @summary Detect printf-family calls where the format argument is not a string literal.
 */
import cpp

from FunctionCall fc, Expr fmt
where fc.getTarget().getName().regexpMatch("printf|fprintf|sprintf|snprintf")
  and fmt = fc.getArgument(0)
  and not fmt instanceof StringLiteral
select fc, "Non-literal format string may expose format-string vulnerability"
