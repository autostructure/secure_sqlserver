#
# This class centralizes log formatting for the module.
#
define secure_sqlserver::log ()
{
  # Enum['alert', 'crit', 'debug', 'emerg', 'err', 'info', 'notice', 'warning'] $threatlevel = hiera('secure_sqlserver::log::threatlevel', 'warning'),# lint:ignore:140chars
  # Boolean $enabled = hiera('secure_sqlserver::log::enabled', true),
  # Enum['alert', 'crit', 'debug', 'emerg', 'err', 'info', 'notice', 'warning'] $threatlevel = 'warning',

  Enum['alert', 'crit', 'debug', 'emerg', 'err', 'info', 'notice', 'warning'] $threatlevel = hiera('secure_sqlserver::log::threatlevel', 'warning')
  Boolean $enabled = hiera('secure_sqlserver::log::enabled', true)

  if $enabled {

    # puppetserver.log
    case $threatlevel {
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
      loglevel => $threatlevel,
    }

  }

}
