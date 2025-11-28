/**
 * @kind problem
 * @id custom/unsafe-copy
 * @problem.severity warning
 * @summary Flags memcpy/strcpy/strcat/sprintf calls (no size checks verified).
 */
import cpp

from FunctionCall fc
where fc.getTarget().getName() in ["memcpy", "strcpy", "strcat", "sprintf"]
select fc, "Potential unsafe copy via " + fc.getTarget().getName()
