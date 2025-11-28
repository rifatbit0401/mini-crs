/**
 * @kind problem
 * @id custom/instant-crash
 * @problem.severity error
 * @summary Flags the intentionally crashing function `instant_crash`.
 */
import cpp

private predicate isInstantCrash(Function f) {
  f.hasName("instant_crash") or
  f.getName().regexpMatch(".*instant_crash.*") or
  f.getQualifiedName().regexpMatch(".*instant_crash.*") or
  exists(FunctionCall fc |
    fc.getTarget() = f and
    fc.getLocation().getFile().getBaseName() = "vuln_lib.c"
  )
}

from Function f
where isInstantCrash(f)
select f, "Function instantly crashes on non-matching input"
