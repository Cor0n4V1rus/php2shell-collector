# php2shell-collector

A command-line interface (CLI) script and infrastructure to collect the results of using [php2shell-scan](https://github.com/0xrsydn/php2shell-scan) to detect CVE-2026-109618 and CVE-2026-109619 in PHP scripts running on (public) web servers.


## Requirements (mandatory) :

- php2shell-scan
- GNU bash (bash)
- GNU coreutils (sleep)

## Requirements (optional; used if found) :

- GNU ncurses (tput)

## Installation

```
mkdir -pv /usr/share/php2shell-collector

install -vm755 php2shell-collector /usr/bin
install -vm644 library.sh          /usr/share/php2shell-collector
```

## Usage

Simple:

```
php2shell-collector help
```

Complex:

```
php2shell-collector verbose:yes format:all output:output-1 input:list-1 HOST-1 ... HOST-n
```


## Options

```
debug:BOOLEAN       Enable bash's 'set -x'.
                    Default is: no.

delay:SECONDS       Delay between probes (in seconds).
                    Default is: 3 seconds.

format:FORMAT       Choose an output format; one of the following:

                    All     All of the below.

                    CSV     CSV data, for import into other applications.
                    HTML    HTML data, to embed in web pages.
                    JSON    JSON data, to process in web pages.
                    List    A textual list, suitable for CLI output.
                    Raw     Raw 'binary' data.
                    Table   A textual table, suitable for CLI output.
                    XML     XML data, for import into other applications

input:PATH          Path to a file, which contains hosts to probe (one per line).
                    Multiple 'input:PATH' parameters may be used, to specify more
                    than one file to use as input.

output:PATH         (Base) Path to a file to store the program's output.

quiet:BOOLEAN       Do not produce any CLI output at all.
                    Default is: no.

simulate:BOOLEAN    Run in simulation mode (or not).
                    Default is: no.

sort:BOOLEAN        Sort the hosts alphabetical (or not).
                    Default is: yes.

timeout:SECONDS     Timeout in seconds, after a probe is aborted.
                    Default is: 30 seconds.

verbose:BOOLEAN     Be verbose about what's currently done.
                    Default is: no.

version[:FORMAT]    Display the program's version in the specified format.
                    If empty, uses the 'Major.Minor.Patch' format.

[HOST 1..n]         A host to probe for.
                    Host(s) specified here are probed before those, coming
                    from input file(s).

```











