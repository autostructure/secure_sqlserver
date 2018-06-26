#
# This class centralizes log formatting for the module.
#
define secure_sqlserver::log (
  Optional[Boolean] $enabled = true,
  Optional[Enum['alert', 'crit', 'debug', 'emerg', 'err', 'info', 'notice', 'warning']] $loglevel = 'debug',
) {

  if $enabled {

    # puppetserver.log
    case $loglevel {
      'alert':   { alert("${facts['fqdn']}: ${title}") }    # always visible
      'crit':    { crit("${facts['fqdn']}: ${title}") }     # always visible
      'debug':   { debug("${facts['fqdn']}: ${title}") }    # visible only with -d or --debug
      'emerg':   { emerg("${facts['fqdn']}: ${title}") }    # always visible
      'err':     { err("${facts['fqdn']}: ${title}") }      # always visible
      'info':    { info("${facts['fqdn']}: ${title}") }     # visible only with -v or --verbose or -d or --debug
      'notice':  { notice("${facts['fqdn']}: ${title}") }   # always visible
      'warning': { warning("${facts['fqdn']}: ${title}") }  # always visible
      default:   { notice("${facts['fqdn']}: ${title}") }   # always visible
    }

    # puppet agent logging
    notify { "puppetagentlogger_${title}":
      withpath => false,
      message  => $title,
      loglevel => $loglevel,
    }

  }

}
