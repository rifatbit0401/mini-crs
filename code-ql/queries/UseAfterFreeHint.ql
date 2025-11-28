/**
 * @kind problem
 * @id custom/use-after-free-hint
 * @problem.severity warning
 * @summary Heuristic: find uses of a variable after a free() in the same function.
 */
import cpp

from Function f, FunctionCall freeCall, VariableAccess freedVar, VariableAccess laterUse
where freeCall.getEnclosingFunction() = f
  and freeCall.getTarget().getName() = "free"
  and freedVar = freeCall.getArgument(0).(VariableAccess)
  and laterUse.getEnclosingFunction() = f
  and laterUse.getTarget() = freedVar.getTarget()
  and laterUse.getLocation().getStartLine() > freeCall.getLocation().getStartLine()
select laterUse, "Heuristic use-after-free of '" + freedVar.getTarget().getName() + "'"
