/**
 * @kind problem
 * @id custom/alloc-mult-overflow
 * @problem.severity warning
 * @summary Flag allocations where the size argument textually includes a multiplication (overflow risk heuristic).
 */
import cpp

from FunctionCall alloc, Expr sz
where alloc.getTarget().getName() in ["malloc", "realloc"]
  and sz = alloc.getArgument(0)
  and sz.toString().regexpMatch(".*\\*.*")
select alloc, "Allocation size involves multiplication; check for overflow"
