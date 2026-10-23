# /*!
#   @project    php2shell-collector
#   
#   @abstract   A simple wrapper infrastructure around 'php2shell-scan'.
#   
#   @discussion This script allows to probe for the
#                   CVE-2026-109618
#               and
#                   CVE-2026-109619
#               remote code execution (RCE) bugs in PHP and collect the results in
#               various data formats for further processing.
#               
#               Handy for server administrators, hosting many websites in various
#               configurations on their machines.
#
#   @section    System Dependencies
#
#   @discussion The following packages are mandatory :
#               
#               php2shell-scan
#               GNU bash        :   bash
#               GNU coreutils   :   sleep
#               
#               The following packages are optional (used, if found) :
#               
#               GNU ncurses     :   tput
#
#
#   @to-do      Implement the 'version' action / CLI parameter.
#
#   @to-do      Import some more of my shell infrastrucutre, to make a few things
#               here and there far easier to maintain ('beautify the source code')
#
#   @to-do      Add the various non-zero result codes, so the script can tell the
#               caller via exit code, what went wrong.
#
#   @to-do      Need to add sort logic; maybe even extend it to a 'real' sort
#               descriptor, instead of just 'sort or not (by host)'.
#
#   @to-do      Need to polish the parsing of php2shell-scan output; found some
#               rare and strange values in the wild here and there!
#
#   @to-do      Add a little bit of more colors here and there, to grasp the
#               important stuff quickly.
#
#   @to-do      Maybe add a few more output formats?
#
#   @to-do      Maybe allow pass-through of some parameters of php2shell-scan?
#
#   @to-do      Create a 'real' documentation from the HeaderDoc comments.
#
#
#   @copyright  Copyright (C) 2026 100% IRDiSCH. ( nhcj@irdisch.de )
#               
#               This program is free software: you can redistribute it and/or modify
#               it under the terms of the GNU General Public License as published by
#               the Free Software Foundation, either version 3 of the License, or
#               (at your option) any later version.
#               
#               This program is distributed in the hope that it will be useful,
#               but WITHOUT ANY WARRANTY; without even the implied warranty of
#               MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#               GNU General Public License for more details.
#               
#               You should have received a copy of the GNU General Public License
#               along with this program.
#               If not, see <https://www.gnu.org/licenses/>.
# */










# /*!
#   @function   php2shell_collector_hosts_collect
#   
#   @abstract   Collect and pre-process the hosts to probe for.
# */

php2shell_collector_hosts_collect ()
{
    local   vLine
    
    set -- "${PHP2SHELL_COLLECTOR_HOST_LIST[@]}"
    
    PHP2SHELL_COLLECTOR_HOST_LIST=()
    
    while test "$#" -gt 0
    do
        case "${PHP2SHELL_COLLECTOR_VERBOSE}"
        in
        1)
            printf  "Processing %s ..\n"    "${1}"
        ;;
        esac
        
        case "${1}"
        in
        https://*)
            PHP2SHELL_COLLECTOR_HOST_LIST+=( "${1}" )
        ;;
        http://*)
            PHP2SHELL_COLLECTOR_HOST_LIST+=( "${1}" )
        ;;
        *)
        #   assume and prepend 'https://' in this case
            
            PHP2SHELL_COLLECTOR_HOST_LIST+=( https://"${1}" )
        ;;
        esac
        
        case "${PHP2SHELL_COLLECTOR_VERBOSE}"
        in
        1)
            printf  "\n"
        ;;
        esac
        
        shift
    done
    
    set -- "${PHP2SHELL_COLLECTOR_INPUT_LIST[@]}"
    
    while test "$#" -gt 0
    do
        case "${PHP2SHELL_COLLECTOR_VERBOSE}"
        in
        1)
            printf  "Reading input file %s ..\n"    "${1}"
        ;;
        esac
        
        while read -r vLine
        do
            case "${vLine}"
            in
            https://*)
                PHP2SHELL_COLLECTOR_HOST_LIST+=( "${vLine}" )
            ;;
            http://*)
                PHP2SHELL_COLLECTOR_HOST_LIST+=( "${vLine}" )
            ;;
            *)
            #   assume and prepend 'https://' in this case
                
                PHP2SHELL_COLLECTOR_HOST_LIST+=( https://"${vLine}" )
            ;;
            esac
            
        done < "${1}"
        
        case "${PHP2SHELL_COLLECTOR_VERBOSE}"
        in
        1)
            printf  "\n"
        ;;
        esac
        
        shift
    done
    
}










# /*!
#   @function   php2shell_collector_help
#   
#   @abstract   Display the help of php2shell-collector.
# */

php2shell_collector_help ()
{
    printf  "php2shell-scanner %s\n"    "${PHP2SHELL_COLLECTOR_VERSION}"
    printf  "Copyright (C) 2026 100%% IRDiSCH.\n"
    printf  "\n"
    printf  "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n"
    printf  "This is free software: you are free to change and redistribute it.\n"
    printf  "There is NO WARRANTY, to the extent permitted by law.\n"
    printf  "\n"
    printf  "\n"
    printf  "A simple wrapper around 'php2shell-scan' to probe for the \n"
    printf  "    CVE-2026-109618 \n"
    printf  "and \n"
    printf  "    CVE-2026-109619 \n"
    printf  "remote code execution (RCE) bugs in PHP and collect the results in\n"
    printf  "various data formats for further processing. \n"
    printf  "\n"
    printf  "Handy for server administrators, hosting many websites on their machines.\n"
    printf  "\n"
    printf  "\n"
    printf  "Parameters:\n"
    printf  "\n"
    printf  "    debug:BOOLEAN      Enable bash's 'set -x'.\n"
    printf  "                       Default is: no.\n"
    printf  "\n"
    printf  "    delay:SECONDS      Delay between probes (in seconds).\n"
    printf  "                       Default is: 3 seconds.\n"
    printf  "\n"
    printf  "    format:FORMAT      Choose an output format; one of the following:\n"
    printf  "\n"
    printf  "                       All     All of the below.\n"
    printf  "\n"
    printf  "                       CSV     CSV data, for import into other applications.\n"
    printf  "                       HTML    HTML data, to embed in web pages.\n"
    printf  "                       JSON    JSON data, to process in web pages.\n"
    printf  "                       List    A textual list, suitable for CLI output.\n"
    printf  "                       Raw     Raw 'binary' data.\n"
    printf  "                       Table   A textual table, suitable for CLI output.\n"
    printf  "                       XML     XML data, for import into other applications\n"
    printf  "\n"
    printf  "    input:PATH         Path to a file, which contains hosts to probe (one per line).\n"
    printf  "                       Multiple 'input:PATH' parameters may be used, to specify more\n"
    printf  "                       than one file to use as input.\n"
    printf  "\n"
    printf  "    output:PATH        (Base) Path to a file to store the program's output.\n"
    printf  "\n"
    printf  "    quiet:BOOLEAN      Do not produce any CLI output at all.\n"
    printf  "                       Default is: no.\n"
    printf  "\n"
    printf  "    simulate:BOOLEAN   Run in simulation mode (or not).\n"
    printf  "                       Default is: no.\n"
    printf  "\n"
    printf  "    sort:BOOLEAN       Sort the hosts alphabetical (or not).\n"
    printf  "                       Default is: yes.\n"
    printf  "\n"
    printf  "    timeout:SECONDS    Timeout in seconds, after a probe is aborted.\n"
    printf  "                       Default is: 30 seconds.\n"
    printf  "\n"
    printf  "    verbose:BOOLEAN    Be verbose about what's currently done.\n"
    printf  "                       Default is: no.\n"
    printf  "\n"
    printf  "    version[:FORMAT]   Display the program's version in the specified format.\n"
    printf  "                       If empty, uses the 'Major.Minor.Patch' format.\n"
    printf  "\n"
    printf  "    [HOST 1..n]        A host to probe for.\n"
    printf  "                       Host(s) specified here are probed before those coming\n"
    printf  "                       from input file(s).\n"
    printf  "\n"
#     printf  "\n"
    
}










# /*!
#   @function   php2shell_collector_initialize
#   
#   @abstract   Initialize the php2shell-collector infrastructure.
# */

php2shell_collector_initialize ()
{
    declare -g  PHP2SHELL_COLLECTOR_VERSION=0.0.1
    
#   external parameters
    
    declare -gi PHP2SHELL_COLLECTOR_DEBUG=0
    declare -gi PHP2SHELL_COLLECTOR_DELAY=3
    declare -ga PHP2SHELL_COLLECTOR_FORMAT=( List )
    declare -gi PHP2SHELL_COLLECTOR_HELP=0
    declare -gi PHP2SHELL_COLLECTOR_QUIET=0
    declare -gi PHP2SHELL_COLLECTOR_SIMULATION=0
    declare -gi PHP2SHELL_COLLECTOR_SORT=1
    declare -gi PHP2SHELL_COLLECTOR_TIMEOUT=30
    declare -gi PHP2SHELL_COLLECTOR_VERBOSE=0
    
    declare -g  PHP2SHELL_COLLECTOR_PHP2SHELL_PATH="$(command -v php2shell-scan)"
    
    declare -ga PHP2SHELL_COLLECTOR_HOST_LIST=()
    declare -ga PHP2SHELL_COLLECTOR_INPUT_LIST=()
    declare -g  PHP2SHELL_COLLECTOR_OUTPUT=
    declare -ga PHP2SHELL_COLLECTOR_SCANS=()
    
#   internal parameters
    
    if command -v tput 1>/dev/null 2>/dev/null
    then
        declare -g  PHP2SHELL_COLOR_BLACK="$(tput setaf 0)"
        declare -g  PHP2SHELL_COLOR_RED="$(tput setaf 1)"
        declare -g  PHP2SHELL_COLOR_GREEN="$(tput setaf 2)"
        declare -g  PHP2SHELL_COLOR_YELLOW="$(tput setaf 3)"
        declare -g  PHP2SHELL_COLOR_BLUE="$(tput setaf 4)"
        declare -g  PHP2SHELL_COLOR_MAGENTA="$(tput setaf 5)"
        declare -g  PHP2SHELL_COLOR_CYAN="$(tput setaf 6)"
        declare -g  PHP2SHELL_COLOR_WHITE="$(tput setaf 7)"
        declare -g  PHP2SHELL_COLOR_RESET="$(tput sgr0)"
    else
        declare -g  PHP2SHELL_COLOR_BLACK=
        declare -g  PHP2SHELL_COLOR_RED=
        declare -g  PHP2SHELL_COLOR_GREEN=
        declare -g  PHP2SHELL_COLOR_YELLOW=
        declare -g  PHP2SHELL_COLOR_BLUE=
        declare -g  PHP2SHELL_COLOR_MAGENTA=
        declare -g  PHP2SHELL_COLOR_CYAN=
        declare -g  PHP2SHELL_COLOR_WHITE=
        declare -g  PHP2SHELL_COLOR_RESET=
    fi
    
    declare -g  PHP2SHELL_COLOR_MITIGATED="${PHP2SHELL_COLOR_GREEN}"
    declare -g  PHP2SHELL_COLOR_IMPROVED="${PHP2SHELL_COLOR_GREEN}"
    declare -g  PHP2SHELL_COLOR_EXPOSED="${PHP2SHELL_COLOR_RED}"
    declare -g  PHP2SHELL_COLOR_UNCHANGED="${PHP2SHELL_COLOR_RED}"
    declare -g  PHP2SHELL_COLOR_CHANGED="${PHP2SHELL_COLOR_MAGENTA}"
    declare -g  PHP2SHELL_COLOR_INCONCLUSIVE="${PHP2SHELL_COLOR_YELLOW}"
    declare -g  PHP2SHELL_COLOR_NO_SIGNAL="${PHP2SHELL_COLOR_CYAN}"
    
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_HOST=0
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_HEADERS=0
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_HINT=0
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_FINGERPRINTS=0
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_PHP_VERSION=0
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_MULTIPART_STATUS=0
    declare -gi PHP2SHELL_COLLECTOR_MAX_LENGTH_PROGRESS=0
    
}










# /*!
#   @function   php2shell_collector_output
#   
#   @abstract   Output the collected data, depending on what the user requested.
# */

php2shell_collector_output ()
{
    local       vOutput
    local -A    vDone
    
    Display.Output ()
    {
        case "${PHP2SHELL_COLLECTOR_QUIET}"
        in
        0)
            printf  "\n"
            printf  "%s :\n"    "${vOutput}"
            printf  "\n"
            cat "${vOutput}"
            printf  "\n"
        ;;
        esac
    }
    
    php2shell_collector_output_preprocess
    
    vDone[CSV]=0
    vDone[HTML]=0
    vDone[JSON]=0
    vDone[List]=0
    vDone[Raw]=0
    vDone[Table]=0
    vDone[XML]=0
    
    set -- "${PHP2SHELL_COLLECTOR_FORMAT[@]}"
    
    while test "$#" -gt 0
    do
        case "${1}"
        in
        C)
            :
        ;;
        C\+\+)
            :
        ;;
        C\#)
            :
        ;;
        CSV)
            if test 0 = "${vDone[CSV]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".csv
                
                php2shell_collector_output_csv      >   "${vOutput}"
                
                Display.Output
                
                vDone[CSV]=1
            fi
        ;;
        Go)
            :
        ;;
        Haskell)
            :
        ;;
        HTML)
            if test 0 = "${vDone[HTML]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".html
                
                php2shell_collector_output_html     >   "${vOutput}"
                
                Display.Output
                
                vDone[HTML]=1
            fi
        ;;
        Java)
            :
        ;;
        JavaScript)
            :
        ;;
        JSON)
            if test 0 = "${vDone[JSON]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".json
                
                php2shell_collector_output_json     >   "${vOutput}"
                
                Display.Output
                
                vDone[JSON]=1
            fi
        ;;
        Kotlin)
            :
        ;;
        LaTeX)
            :
        ;;
        List)
            if test 0 = "${vDone[List]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".list
                
                php2shell_collector_output_list     >   "${vOutput}"
                
                Display.Output
                
                vDone[List]=1
            fi
        ;;
        NDJSON)
            :
        ;;
        ODS)
            :
        ;;
        PDF)
            :
        ;;
        Perl)
            :
        ;;
        PHP)
            :
        ;;
        Python)
            :
        ;;
        R)
            :
        ;;
        Raw)
            if test 0 = "${vDone[Raw]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".raw
                
                php2shell_collector_output_raw      >   "${vOutput}"
                
                Display.Output
                
                vDone[Raw]=1
            fi
        ;;
        reStructuredText)
            :
        ;;
        Ruby)
            :
        ;;
        Rust)
            :
        ;;
        SQL)
            :
        ;;
        Table)
            if test 0 = "${vDone[Table]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".table
                
                php2shell_collector_output_table    >   "${vOutput}"
                
                Display.Output
                
                vDone[Table]=1
            fi
        ;;
        TSV)
            :
        ;;
        TypeScript)
            :
        ;;
        XLSX)
            :
        ;;
        XML)
            if test 0 = "${vDone[XML]}"
            then
                vOutput="${PHP2SHELL_COLLECTOR_OUTPUT}".xml
                
                php2shell_collector_output_xml      >   "${vOutput}"
                
                Display.Output
                
                vDone[XML]=1
            fi
        ;;
        YAML)
            :
        ;;
        esac
        
        shift
    done
    
}










# /*!
#   @function   php2shell_collector_output_preprocess
#   
#   @abstract   Do required preprocessing on the collected data.
# */

php2shell_collector_output_preprocess ()
{
    
    :
    
}










# /*!
#   @function   php2shell_collector_output_csv
#   
#   @abstract   
#
#   @note       
# */

php2shell_collector_output_csv ()
{
    local -i    vIndex
    local -i    vMax
    
    local        vFieldSep=';'
    local       vRecordSep=$'\n'
    local       vQuoteLeft="'"
    local       vQuoteRight="'"
    
    Head1 ()
    {
        printf  "%s%s"  "${1}"  "${vFieldSep}"
    }
    
    Head2 ()
    {
        printf  "%s\n"  "${1}"
    }
    
    Field ()
    {
        printf  "%s%s%s%s"  "${vQuoteLeft}" \
                            "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}" \
                            "${vQuoteRight}" \
                            "${vFieldSep}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    Record ()
    {
        printf  "\"%s\"%s"  "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}" "${vRecordSep}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    vMax="${#PHP2SHELL_COLLECTOR_SCANS[@]}"
    
    Head1   Host
    Head1   Timestamp
    Head1   Verdict
    Head1   Headers
    Head1   Hint
    Head1   Fingerprints
    Head1   PHP_Version
    Head1   Multipart_Status
    Head1   Multipart_Code
    Head1   Progress
    Head1   Upload_1Mb
    Head1   Upload_8Mb
    Head2   Upload_32Mb
    
    for (( vIndex=0 ; vIndex < vMax ; ))
    do
        Field   #   host
        Field   #   timestamp
        Field   #   verdict
        Field   #   headers
        Field   #   hint
        Field   #   fingerprints
        Field   #   php_version
        Field   #   multipart_status
        Field   #   multipart_code
        Field   #   progress
        Field   #   upload_1mb
        Field   #   upload_8mb
        Record  #   upload_32mb
        
    done
    
}










# /*!
#   @function   php2shell_collector_output_html
#   
#   @abstract   
#
#   @note       Produces something like
#               
#               <TABLE>
#               <TR>
#               <TH><SPAN class="php2shell_collector_host">https://www.example.net</SPAN></TH>
#               <TD><SPAN class="php2shell_collector_timestamp">2026-10-20T12:24:56Z</SPAN></TD>
#               <TD><SPAN class="php2shell_collector_verdict">exposed</SPAN></TD>
#               <TD><SPAN class="php2shell_collector_headers"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_hint"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_fingerprints"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_php_version"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_multipart_status"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_multipart_code"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_progress"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_upload_1mb"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_upload_8mb"></SPAN></TD>
#               <TD><SPAN class="php2shell_collector_upload_32mb"></SPAN></TD>
#               </TR>
#               ...
#               </TABLE>
# */

php2shell_collector_output_html ()
{
    local -i    vIndex
    local -i    vMax
    
    SPAN ()
    {
        local   pClass="${1}"
        
        printf  "<SPAN class=\"%s\">"   "${pClass}"
        printf  "%s"            "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}"
        printf  "</SPAN>"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    TH ()
    {
        printf  "<TH scope=\"row\">"
        SPAN    php2shell_collector_host
        printf  "</TH>"
        
    }
    
    TD ()
    {
        local   pClass="${1}"
        
        printf  "<TD>"
        SPAN    php2shell_collector_"${pClass}"
        printf  "</TD>"
        
    }
    
    vMax="${#PHP2SHELL_COLLECTOR_SCANS[@]}"
    
    printf  "<TABLE>\n"
    
    printf  "<THEAD>\n"
    printf  "<TR>\n"
    printf  "<TH scope=\"col\">Host</TH>\n"
    printf  "<TH scope=\"col\">Timestamp</TH>\n"
    printf  "<TH scope=\"col\">Verdict</TH>\n"
    printf  "<TH scope=\"col\">Headers</TH>\n"
    printf  "<TH scope=\"col\">Hint</TH>\n"
    printf  "<TH scope=\"col\">Fingerprints</TH>\n"
    printf  "<TH scope=\"col\">PHP Version</TH>\n"
    printf  "<TH scope=\"col\">Multipart Status</TH>\n"
    printf  "<TH scope=\"col\">Multipart Code</TH>\n"
    printf  "<TH scope=\"col\">Progress</TH>\n"
    printf  "<TH scope=\"col\">Upload (1Mb)</TH>\n"
    printf  "<TH scope=\"col\">Upload (8Mb)</TH>\n"
    printf  "<TH scope=\"col\">Upload (32Mb)</TH>\n"
    printf  "</TR>\n"
    printf  "</THEAD>\n"
    
    for (( vIndex=0 ; vIndex < vMax ; ))
    do
        printf  "<TR>\n"
        
        TH
        TD  php2shell_collector_timestamp
        TD  php2shell_collector_verdict
        TD  php2shell_collector_headers
        TD  php2shell_collector_hint
        TD  php2shell_collector_fingerprints
        TD  php2shell_collector_php_version
        TD  php2shell_collector_multipart_status
        TD  php2shell_collector_multipart_code
        TD  php2shell_collector_progress
        TD  php2shell_collector_upload_1mb
        TD  php2shell_collector_upload_8mb
        TD  php2shell_collector_upload_32mb
        
        printf  "</TR>\n"
    done
    
    printf  "</TABLE>\n"
    
}










# /*!
#   @function   php2shell_collector_output_json
#   
#   @abstract   
#
#   @note       Produces something like
#               
#               [
#               {
#               "Host": "https://www.example.net",
#               "Timestamp": "2026-10-20T12:24:56Z",
#               "Verdict": "exposed",
#               "Headers": "",
#               "Hint": "",
#               "Fingerprints": "",
#               "PHPVersion": "",
#               "MultipartStatus": "ok",
#               "MultipartCode": "200",
#               "Progress": "ok",
#               "Upload1Mb": "200",
#               "Upload8Mb": "200",
#               "Upload32Mb": "403"
#               },
#               ...
#               ]
# */

php2shell_collector_output_json ()
{
    local -i    vIndex
    local -i    vMax
    
    Field1 ()
    {
        local   pKey="${1}"
        
        printf  "\"%s\": \"%s\",\n" "${pKey}" "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    Field2 ()
    {
        local   pKey="${1}"
        
        printf  "\"%s\": \"%s\"\n"  "${pKey}" "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    vMax="${#PHP2SHELL_COLLECTOR_SCANS[@]}"
    
    printf  "[\n"
    
    for (( vIndex=0 ; vIndex < vMax ; ))
    do
        printf  "{\n"
        
        Field1  Host
        Field1  Timestamp
        Field1  Verdict
        Field1  Headers
        Field1  Hint
        Field1  Fingerprints
        Field1  PHPVersion
        Field1  MultipartStatus
        Field1  MultipartCode
        Field1  Progress
        Field1  Upload1Mb
        Field1  Upload8Mb
        Field2  Upload32Mb
        
        printf  "},\n"
    done
    
    printf  "]\n"
    
}










# /*!
#   @function   php2shell_collector_output_list
#   
#   @abstract   
#
#   @note       TIMESTAMP   [Verdict]    https://www.example.com     ... ... ...
#               TIMESTAMP   [Verdict]    https://www.example.net     ... ... ...
# */

php2shell_collector_output_list ()
{
    local -i    vIndex
    local -i    vMax
    
    local       vField
    
    local -i    vPadHost="${PHP2SHELL_COLLECTOR_MAX_LENGTH_HOST}"
    local -i    vPadHeaders="${PHP2SHELL_COLLECTOR_MAX_LENGTH_HEADERS}"
    local -i    vPadHint="${PHP2SHELL_COLLECTOR_MAX_LENGTH_HINT}"
    local -i    vPadFingerprints="${PHP2SHELL_COLLECTOR_MAX_LENGTH_FINGERPRINTS}"
    local -i    vPadPHPVersion="${PHP2SHELL_COLLECTOR_MAX_LENGTH_PHP_VERSION}"
    local -i    vPadMultipartStatus="${PHP2SHELL_COLLECTOR_MAX_LENGTH_MULTIPART_STATUS}"
    local -i    vPadProgress="${PHP2SHELL_COLLECTOR_MAX_LENGTH_PROGRESS}"
    
    vPadHost=$(( vPadHost + (4 - (vPadHost % 4)) ))
    vPadHeaders=$(( vPadHeaders + (4 - (vPadHeaders % 4)) ))
    vPadHint=$(( vPadHint + (4 - (vPadHint % 4)) ))
    vPadFingerprints=$(( vPadFingerprints + (4 - (vPadFingerprints % 4)) ))
    vPadPHPVersion=$(( vPadPHPVersion + (4 - (vPadPHPVersion % 4)) ))
    vPadMultipartStatus=$(( vPadMultipartStatus + (4 - (vPadMultipartStatus % 4)) ))
    vPadProgress=$(( vPadProgress + (4 - (vPadProgress % 4)) ))
    
    vMax="${#PHP2SHELL_COLLECTOR_SCANS[@]}"
    
    for (( vIndex=0 ; vIndex < vMax ; ))
    do
    #   timestamp
        
        printf  "%s  "                      "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+1))]}"
        
    #   verdict
        
        vField="${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+2))]}"
        
        case "${vField,,}"
        in
        mitigated)      printf  "%s"    "${PHP2SHELL_COLOR_MITIGATED}"      ;;
        improved)       printf  "%s"    "${PHP2SHELL_COLOR_IMPROVED}"       ;;
        exposed)        printf  "%s"    "${PHP2SHELL_COLOR_EXPOSED}"        ;;
        unchanged)      printf  "%s"    "${PHP2SHELL_COLOR_UNCHANGED}"      ;;
        changed)        printf  "%s"    "${PHP2SHELL_COLOR_CHANGED}"        ;;
        inconclusive)   printf  "%s"    "${PHP2SHELL_COLOR_INCONCLUSIVE}"   ;;
        no_signal)      printf  "%s"    "${PHP2SHELL_COLOR_NO_SIGNAL}"      ;;
        esac
        
        printf  "%-12s"                     "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+2))]}"
        printf  "%s  "                      "${PHP2SHELL_COLOR_RESET}"
        
    #   host
        
        printf  "%-${vPadHost}s"            "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+0))]}"   #   host
        printf  "%-${vPadHeaders}s"         "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+3))]}"   #   headers
        printf  "%-${vPadHint}s"            "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+4))]}"   #   hint
        printf  "%-${vPadFingerprints}s"    "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+5))]}"   #   fingerprints
        printf  "%-${vPadPHPVersion}s"      "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+6))]}"   #   php version
        printf  "%-${vPadMultipartStatus}s" "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+7))]}"   #   multipart status
        
    #   multipart code
        
        vField="${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+8))]}"
        
        case "${vField}"
        in
        2*) printf  "%s"    "${PHP2SHELL_COLOR_GREEN}"  ;;
        4*) printf  "%s"    "${PHP2SHELL_COLOR_RED}"    ;;
        5*) printf  "%s"    "${PHP2SHELL_COLOR_YELLOW}" ;;
        esac
        
        printf  "%-3s"      "${vField}"
        printf  "%s "       "${PHP2SHELL_COLOR_RESET}"
        
    #   progress
        
        printf  "%-${vPadProgress}s"        "${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+9))]}"
        
    #   upload 1mb
        
        vField="${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+10))]}"
        
        case "${vField}"
        in
        2*) printf  "%s"    "${PHP2SHELL_COLOR_GREEN}"  ;;
        4*) printf  "%s"    "${PHP2SHELL_COLOR_RED}"    ;;
        5*) printf  "%s"    "${PHP2SHELL_COLOR_YELLOW}" ;;
        esac
        
        printf  "%-3s"      "${vField}"
        printf  "%s "       "${PHP2SHELL_COLOR_RESET}"
        
    #   upload 8mb
        
        vField="${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+11))]}"
        
        case "${vField}"
        in
        2*) printf  "%s"    "${PHP2SHELL_COLOR_GREEN}"  ;;
        4*) printf  "%s"    "${PHP2SHELL_COLOR_RED}"    ;;
        5*) printf  "%s"    "${PHP2SHELL_COLOR_YELLOW}" ;;
        esac
        
        printf  "%-3s"      "${vField}"
        printf  "%s "       "${PHP2SHELL_COLOR_RESET}"
        
    #   upload 32mb
        
        vField="${PHP2SHELL_COLLECTOR_SCANS[$((vIndex+12))]}"
        
        case "${vField}"
        in
        2*) printf  "%s"    "${PHP2SHELL_COLOR_GREEN}"  ;;
        4*) printf  "%s"    "${PHP2SHELL_COLOR_RED}"    ;;
        5*) printf  "%s"    "${PHP2SHELL_COLOR_YELLOW}" ;;
        esac
        
        printf  "%-3s"      "${vField}"
        printf  "%s "       "${PHP2SHELL_COLOR_RESET}"
        
        printf  "\n"
        
        vIndex=$(( vIndex + 13 ))
    done
    
}










# /*!
#   @function   php2shell_collector_output_raw
#   
#   @abstract   Output the collected data as it is, with the
#                   'Unit Separator' (0x1F)
#               control character as field separator and the
#                   'Record Separator' (0x1E)
#               control character as record separator.
#
#   @note       
# */

php2shell_collector_output_raw ()
{
    local -i    vIndex
    local -i    vMax
    
    local        vFieldSep=$'\x1F'
    local       vRecordSep=$'\x1E'
    
    Field ()
    {
        printf  "%s%s"  "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}" "${vFieldSep}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    Record ()
    {
        printf  "%s%s"  "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}" "${vRecordSep}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    vMax="${#PHP2SHELL_COLLECTOR_SCANS[@]}"
    
    for (( vIndex=0 ; vIndex < vMax ; ))
    do
        Field   #   host
        Field   #   timestamp
        Field   #   verdict
        Field   #   headers
        Field   #   hint
        Field   #   fingerprints
        Field   #   php_version
        Field   #   multipart_status
        Field   #   multipart_code
        Field   #   progress
        Field   #   upload_1mb
        Field   #   upload_8mb
        Record  #   upload_32mb
        
    done
    
}










# /*!
#   @function   php2shell_collector_output_table
#   
#   @abstract   Output the collected data as simple table.
#
#   @note       +- Host ------------------+- Status -+- xxxx -+- xxxx -+- xxxx -+- xxxx -+
#               | https://www.example.net |
# */

php2shell_collector_output_table ()
{
    :
    
    
}










# /*!
#   @function   php2shell_collector_output_xml
#   
#   @abstract   Output the collected data as XML data.
#
#   @note       Produces something like
#               
#               <?xml version="1.0" encoding="UTF-8"?>
#               <TABLE>
#               <ROW>
#               <Host>https://www.example.net</Host>
#               <Timestamp>2026-10-20T12:34:56Z</Timestamp>
#               <Verdict>exposed</Verdict>
#               <Headers></Headers>
#               <Hint>Apache</Hint>
#               <Fingerprints></Fingerprints>
#               <PHPVersion></PHPVersion>
#               <MultipartStatus>ok</MultipartStatus>
#               <MultipartCode>200</MultipartCode>
#               <Progress>ok</Progress>
#               <Upload1Mb>200</Upload1Mb>
#               <Upload8Mb>200</Upload8Mb>
#               <Upload32Mb>403</Upload32Mb>
#               </ROW>
#               ...
#               </TABLE>
# */

php2shell_collector_output_xml ()
{
    local -i    vIndex
    local -i    vMax
    
    Pair ()
    {
        local   pEntity="${1}"
        
        printf  "<%s>"      "${pEntity}"
        printf  "%s"        "${PHP2SHELL_COLLECTOR_SCANS[${vIndex}]}"
        printf  "</%s>\n"   "${pEntity}"
        
        vIndex=$(( vIndex + 1 ))
    }
    
    vMax="${#PHP2SHELL_COLLECTOR_SCANS[@]}"
    
    printf  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    printf  "<TABLE>\n"
    
    for (( vIndex=0 ; vIndex < vMax ; ))
    do
        printf  "<ROW>\n"
        
        Pair    Host
        Pair    Timestamp
        Pair    Verdict
        Pair    Headers
        Pair    Hint
        Pair    Fingerprints
        Pair    PHPVersion
        Pair    MultipartStatus
        Pair    MultipartCode
        Pair    Progress
        Pair    Upload1Mb
        Pair    Upload8Mb
        Pair    Upload32Mb
        
        printf  "</ROW>\n"
    done
    
    printf  "</TABLE>\n"
    
}










# /*!
#   @function   php2shell_collector_parameters_display
#   
#   @abstract   For debugging purposes, display the current state of parameters.
# */

php2shell_collector_parameters_display ()
{
    
    php2shell_collector_parameters_display_path       PHP2SHELL_COLLECTOR_PHP2SHELL_PATH
    printf  "\n"
    php2shell_collector_parameters_display_boolean    PHP2SHELL_COLLECTOR_DEBUG
    php2shell_collector_parameters_display_boolean    PHP2SHELL_COLLECTOR_HELP
    php2shell_collector_parameters_display_boolean    PHP2SHELL_COLLECTOR_QUIET
    php2shell_collector_parameters_display_boolean    PHP2SHELL_COLLECTOR_SIMULATION
    php2shell_collector_parameters_display_boolean    PHP2SHELL_COLLECTOR_VERBOSE
    printf  "\n"
    php2shell_collector_parameters_display_number     PHP2SHELL_COLLECTOR_DELAY
    php2shell_collector_parameters_display_number     PHP2SHELL_COLLECTOR_TIMEOUT
    php2shell_collector_parameters_display_boolean    PHP2SHELL_COLLECTOR_SORT
    php2shell_collector_parameters_display_list       PHP2SHELL_COLLECTOR_FORMAT
    printf  "\n"
    php2shell_collector_parameters_display_list       PHP2SHELL_COLLECTOR_INPUT_LIST
    php2shell_collector_parameters_display_path       PHP2SHELL_COLLECTOR_OUTPUT
    printf  "\n"
    php2shell_collector_parameters_display_list       PHP2SHELL_COLLECTOR_HOST_LIST
    
    
    
}










# /*!
#   @function   php2shell_collector_parameters_display_boolean
#   
#   @abstract   Display a boolean parameter.
# */

php2shell_collector_parameters_display_boolean ()
{
    local       pVariable="${1}"
    
    local -n    rVariable="${1}"
    
    printf  "%s%-36s%s    :   " \
            "${PHP2SHELL_COLOR_CYAN}" \
            "${pVariable}" \
            "${PHP2SHELL_COLOR_RESET}"
    
    case "${rVariable}"
    in
    0)
        printf  "%s" \
                "${PHP2SHELL_COLOR_RED}"
    ;;
    1)
        printf  "%s" \
                "${PHP2SHELL_COLOR_GREEN}"
    ;;
    esac
    
    printf  "%s%s\n" \
            "${rVariable}" \
            "${PHP2SHELL_COLOR_RESET}"
    
}










# /*!
#   @function   php2shell_collector_parameters_display_list
#   
#   @abstract   Display a list parameter.
# */

php2shell_collector_parameters_display_list ()
{
    local       pVariable="${1}"
    
    local -n    rVariable="${1}"
    
    printf  "%s%-36s%s [] :   " \
            "${PHP2SHELL_COLOR_WHITE}" \
            "${pVariable}" \
            "${PHP2SHELL_COLOR_RESET}"
    
    set --  "${rVariable[@]}"
    
    if test "$#" -gt 0
    then
        printf  "'%s'\n"    "${1}"
        shift
        
        while test "$#" -ge 1
        do
            printf  "%-44s'%s'\n"    ' ' "${1}"
            shift
        done
    else
        printf  "\n"
    fi
    
}










# /*!
#   @function   php2shell_collector_parameters_display_number
#   
#   @abstract   Display a number parameter.
# */

php2shell_collector_parameters_display_number ()
{
    local       pVariable="${1}"
    
    local -n    rVariable="${1}"
    
    printf  "%s%-36s%s    :   %s\n" \
            "${PHP2SHELL_COLOR_CYAN}" \
            "${pVariable}" \
            "${PHP2SHELL_COLOR_RESET}" \
            "${rVariable}"
    
}










# /*!
#   @function   php2shell_collector_parameters_display_path
#   
#   @abstract   Display a path parameter.
# */

php2shell_collector_parameters_display_path ()
{
    local       pVariable="${1}"
    
    local -n    rVariable="${1}"
    
    printf  "%s%-36s%s    :   " \
            "${PHP2SHELL_COLOR_MAGENTA}" \
            "${pVariable}" \
            "${PHP2SHELL_COLOR_RESET}"
    
    if test -f "${rVariable}"
    then
        printf  "%s" \
                "${PHP2SHELL_COLOR_GREEN}"
    else
        printf  "%s" \
                "${PHP2SHELL_COLOR_RED}"
    fi
    
    printf  "%s%s\n" \
            "${rVariable}" \
            "${PHP2SHELL_COLOR_RESET}"
    
}










# /*!
#   @function   php2shell_collector_parameters_display_text
#   
#   @abstract   Display a text parameter.
# */

php2shell_collector_parameters_display_text ()
{
    local       pVariable="${1}"
    
    local -n    rVariable="${1}"
    
    printf  "%s%-36s%s    :   '%s'\n" \
            "${PHP2SHELL_COLOR_WHITE}" \
            "${pVariable}" \
            "${PHP2SHELL_COLOR_RESET}" \
            "${rVariable}"
    
}










# /*!
#   @function   php2shell_collector_parameters_display_url
#   
#   @abstract   Display an url parameter.
# */

php2shell_collector_parameters_display_url ()
{
    local       pVariable="${1}"
    
    local -n    rVariable="${1}"
    
    printf  "%s%-32s%s    :   '%s'\n" \
            "${PHP2SHELL_COLOR_MAGENTA}" \
            "${pVariable}" \
            "${PHP2SHELL_COLOR_RESET}" \
            "${rVariable}"
    
}










# /*!
#   @function   php2shell_collector_parameters_parse
#   
#   @abstract   Parse the supplied parameters.
# */

php2shell_collector_parameters_parse ()
{
    local   pKey
    local   pValue
    
    while   test "$#" -gt 0
    do
          pKey="${1}"
        pValue="${pKey#*:}"
        
#         declare -p pKey pValue
        
        case "${pKey,,}"
        in
        debug:*)
            case "${pValue}"
            in
            0|false|no)
                PHP2SHELL_COLLECTOR_DEBUG=0
            ;;
            1|true|yes)
                PHP2SHELL_COLLECTOR_DEBUG=1
            ;;
            *)
                printf  "Invalid value for parameter 'debug:BOOLEAN' !\n"
            ;;
            esac
        ;;
        delay:*)
            if test -n "${pValue}"
            then
                if [[ $pValue =~ ^[0-9]+$ ]]
                then
                    if (( 10#$pValue >= 0 && 10#$pValue <= 300 ))
                    then
                        PHP2SHELL_COLLECTOR_DELAY="${pValue}"
                    else
                        printf  "Invalid value for parameter 'delay:SECONDS';\n"
                        printf  "must be between 0 and 300 !\n"
                    fi
                else
                    printf  "Non-digit value for parameter 'delay:SECONDS' !\n"
                fi
            else
                printf  "Empty value for parameter 'delay:SECONDS' !\n"
            fi
        ;;
        format:*)
            if test -n "${pValue}"
            then
                case "${pValue,,}"
                in
                all)
                    PHP2SHELL_COLLECTOR_FORMAT+=( CSV HTML JSON List Raw Table XML )
                ;;
                csv)
                    PHP2SHELL_COLLECTOR_FORMAT+=( CSV )
                ;;
                html)
                    PHP2SHELL_COLLECTOR_FORMAT+=( HTML )
                ;;
                json)
                    PHP2SHELL_COLLECTOR_FORMAT+=( JSON )
                ;;
                list)
                    PHP2SHELL_COLLECTOR_FORMAT+=( List )
                ;;
                raw)
                    PHP2SHELL_COLLECTOR_FORMAT+=( Raw )
                ;;
                table)
                    PHP2SHELL_COLLECTOR_FORMAT+=( Table )
                ;;
                xml)
                    PHP2SHELL_COLLECTOR_FORMAT+=( XML )
                ;;
                *)
                    printf  "Invalid value for parameter 'format:FORMAT';\n"
                    printf  "must be 'List' or 'Table' !\n"
                ;;
                esac
            else
                printf  "Empty value for parameter 'format:FORMAT' !\n"
            fi
        ;;
        input:*)
            if test -n "${pValue}"
            then
                if test -f "${pValue}"
                then
                    if test -r "${pValue}"
                    then
                        PHP2SHELL_COLLECTOR_INPUT_LIST+=( "${pValue}" )
                    else
                        printf  "Non-readable path for parameter 'input' !\n"
                    fi
                else
                    printf  "Non-readable path for parameter 'input' !\n"
                fi
            else
                printf  "Empty value for parameter 'input:PATH' !\n"
            fi
        ;;
        output:*)
            if test -n "${pValue}"
            then
                PHP2SHELL_COLLECTOR_OUTPUT="${pValue}"
            else
                printf  "Empty value for parameter 'output:PATH' !\n"
            fi
        ;;
        simulate:*)
            case "${pValue}"
            in
            0|false|no)
                PHP2SHELL_COLLECTOR_SIMULATION=0
            ;;
            1|true|yes)
                PHP2SHELL_COLLECTOR_SIMULATION=1
            ;;
            *)
                printf  "Invalid value for parameter 'simulate:BOOLEAN' !\n"
            ;;
            esac
        ;;
        sort:*)
            case "${pValue}"
            in
            0|false|no)
                PHP2SHELL_COLLECTOR_SORT=0
            ;;
            1|true|yes)
                PHP2SHELL_COLLECTOR_SORT=1
            ;;
            *)
                printf  "Invalid value for parameter 'sort:BOOLEAN' !\n"
            ;;
            esac
        ;;
        timeout:*)
            if test -n "${pValue}"
            then
                if [[ $pValue =~ ^[0-9]+$ ]]
                then
                    if (( 10#$pValue >= 0 && 10#$pValue <= 300 ))
                    then
                        PHP2SHELL_COLLECTOR_TIMEOUT="${pValue}"
                    else
                        printf  "Invalid value for parameter 'timeout:SECONDS';\n"
                        printf  "must be between 0 and 300 !\n"
                    fi
                else
                    printf  "Non-digit value for parameter 'timeout:SECONDS' !\n"
                fi
            else
                printf  "Empty value for parameter 'timeout:SECONDS' !\n"
            fi
        ;;
        verbose:*)
            case "${pValue}"
            in
            0|false|no)
                PHP2SHELL_COLLECTOR_VERBOSE=0
            ;;
            1|true|yes)
                PHP2SHELL_COLLECTOR_VERBOSE=1
            ;;
            *)
                printf  "Invalid value for parameter 'verbose:BOOLEAN' !\n"
            ;;
            esac
        ;;
        help|usage)
            PHP2SHELL_COLLECTOR_HELP=1
        ;;
        *)
            PHP2SHELL_COLLECTOR_HOST_LIST+=( "${1}" )
        ;;
        esac
        
        shift
    done
    
}










# /*!
#   @function   php2shell_collector_probe
#   
#   @abstract   The actual wrapper of 'php2shell-scan', to extract the determined
#               information.
#
#   @note       An example output would be :
#               
#               php2shell-scan probe https://www.example.net
#               
#               probe https://www.example.net  [2026-10-20T12:34:56Z]
#               VERDICT: exposed — PHP parses attacker multipart pre-auth: CVE surface is reachable
#                 - multipart POST parsed by PHP -> 200 (ok)
#                 - upload-progress field accepted on the same path
#                 server_headers: {}
#                 server_hint: ["x-powered-by stripped"]
#                 fingerprints: {}
#                 php_min_guess: null
#                 multipart: {"status": "ok", "code": 200}
#                 upload_progress: {"status": "ok"}
#                 uploads: {"1mb": 200, "8mb": 200, "32mb": 403}
# */

php2shell_collector_probe ()
{
    local       pHost="${1}"
    
    local -a    vCommand=()
    local -a    vLine=()
    local -i    vLength=0
    
    local       vTimestamp
    local       vVerdict
    local       vHeaders
    local       vHint
    local       vFingerprints
    local       vPHPVersion
    local       vMultipartStatus
    local       vMultipartCode
    local       vProgress
    local       vUpload1Mb
    local       vUpload8Mb
    local       vUpload32Mb
    local       vJunk
    
    vCommand+=( "${PHP2SHELL_COLLECTOR_PHP2SHELL_PATH}" )
    vCommand+=( probe )
    vCommand+=( "${pHost}" )
    
    while IFS=$' \n' read -r -a vLine
    do
        case "${PHP2SHELL_COLLECTOR_VERBOSE}"
        in
        1)
            declare -p vLine
            printf  "\n"
        ;;
        esac
        
        case "${vLine[0]}"
        in
        probe)
            vTimestamp="${vLine[2]}"
            vTimestamp="${vTimestamp/$'['/}"
            vTimestamp="${vTimestamp/$']'/}"
        ;;
        VERDICT:)
            vVerdict="${vLine[1]}"
        ;;
        server_headers:)
            vHeaders="${vLine[@]:1}"
            vHeaders="${vHeaders//\{/}"
            vHeaders="${vHeaders//\}/}"
            vHeaders="${vHeaders//: \"/:\"}"
        ;;
        server_hint:)
            case "${vLine[2]}"
            in
            stripped*)
                vHint=
            ;;
            *)
                vHint="${vLine[1]}"
                vHint="${vHint//\[/}"
                vHint="${vHint//\]/}"
            ;;
            esac
        ;;
        fingerprints:)
            case "${vLine[1]}"
            in
            '{}')
                vFingerprints=
            ;;
            *)
                vFingerprints="${vLine[1]}${vLine[2]}"
                vFingerprints="${vFingerprints//\{/}"
                vFingerprints="${vFingerprints//\}/}"
            ;;
            esac
        ;;
        php_min_guess:)
            vPHPVersion="${vLine[1]}"
            vPHPVersion="${vPHPVersion/null/}"
        ;;
        multipart:)
            vMultipartStatus="${vLine[2]}"
            vMultipartStatus="${vMultipartStatus//\"/}"
            vMultipartStatus="${vMultipartStatus//,/}"
            
            vMultipartCode="${vLine[4]}"
            vMultipartCode="${vMultipartCode//\}/}"
        ;;
        upload_progress:)
            vProgress="${vLine[2]}"
            vProgress="${vProgress//\}/}"
            vProgress="${vProgress//\"/}"
        ;;
        uploads:)
            vUpload1Mb="${vLine[2]}"
            vUpload1Mb="${vUpload1Mb/,/}"
            
            vUpload8Mb="${vLine[4]}"
            vUpload8Mb="${vUpload8Mb/,/}"
            
            vUpload32Mb="${vLine[6]}"
            vUpload32Mb="${vUpload32Mb/$'}'/}"
        ;;
        esac
        
    done <<< "$( ${vCommand[@]} )"
    
    case "${PHP2SHELL_COLLECTOR_VERBOSE}"
    in
    1)
        printf  "\n"
        printf  "Host               : '%s'\n" "${pHost}"
        printf  "Timestamp          : '%s'\n" "${vTimestamp}"
        printf  "Verdict            : '%s'\n" "${vVerdict}"
        printf  "Headers            : '%s'\n" "${vHeaders}"
        printf  "Hint               : '%s'\n" "${vHint}"
        printf  "Fingerprints       : '%s'\n" "${vFingerprints}"
        printf  "PHP Min. Version   : '%s'\n" "${vPHPVersion}"
        printf  "Multipart Status   : '%s'\n" "${vMultipartStatus}"
        printf  "Multipart Code     : '%s'\n" "${vMultipartCode}"
        printf  "Upload Progress    : '%s'\n" "${vProgress}"
        printf  "Upload 1|8|32 Mb   : '%s' '%s' '%s'\n" \
                "${vUpload1Mb}" "${vUpload8Mb}" "${vUpload32Mb}"
        
        printf  "\n"
    ;;
    esac
    
#   each record consists of these 13 fields :
    
    PHP2SHELL_COLLECTOR_SCANS+=( "${pHost}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vTimestamp}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vVerdict}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vHeaders}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vHint}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vFingerprints}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vPHPVersion}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vMultipartStatus}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vMultipartCode}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vProgress}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vUpload1Mb}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vUpload8Mb}" )
    PHP2SHELL_COLLECTOR_SCANS+=( "${vUpload32Mb}" )
    
#   also do some evaluation for the output later
    
    vLength="${#pHost}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_HOST}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_HOST="${vLength}"
    fi
    
    vLength="${#vHeaders}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_HEADERS}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_HEADERS="${vLength}"
    fi
    
    vLength="${#vHint}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_HINT}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_HINT="${vLength}"
    fi
    
    vLength="${#vFingerprints}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_FINGERPRINTS}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_FINGERPRINTS="${vLength}"
    fi
    
    vLength="${#vPHPVersion}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_PHP_VERSION}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_PHP_VERSION="${vLength}"
    fi
    
    vLength="${#vMultipartStatus}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_MULTIPART_STATUS}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_MULTIPART_STATUS="${vLength}"
    fi
    
    vLength="${#vProgress}"
    
    if test "${vLength}" -gt "${PHP2SHELL_COLLECTOR_MAX_LENGTH_PROGRESS}"
    then
        PHP2SHELL_COLLECTOR_MAX_LENGTH_PROGRESS="${vLength}"
    fi
    
}










# /*!
#   @function   php2shell_collector_run
#   
#   @abstract   Run the program, based on previously parsed parameters.
# */

php2shell_collector_run ()
{
    local   vPath
    local   vParent
    
    case "${PHP2SHELL_COLLECTOR_DEBUG}"
    in
    1)
        set -x
    ;;
    esac
    
    case "${PHP2SHELL_COLLECTOR_VERBOSE}"
    in
    1)
        php2shell_collector_parameters_display
    ;;
    esac
    
    case "${PHP2SHELL_COLLECTOR_HELP}"
    in
    1)
        php2shell_collector_help
    ;;
    esac
    
    php2shell_collector_hosts_collect
    
    if test "${#PHP2SHELL_COLLECTOR_HOST_LIST[@]}" -gt 0
    then
        if test -z "${PHP2SHELL_COLLECTOR_OUTPUT}"
        then
        #   use default path(s)
            
            mkdir -p    /tmp/php2shell-collector
            
            PHP2SHELL_COLLECTOR_OUTPUT="$(mktemp /tmp/php2shell-collector/collection.XXXXXXXX)"
        fi
        
        case "${PHP2SHELL_COLLECTOR_VERBOSE}"
        in
        1)
            php2shell_collector_parameters_display_list       PHP2SHELL_COLLECTOR_HOST_LIST
        ;;
        esac
        
        PHP2SHELL_COLLECTOR_SCANS=()
        
        set -- "${PHP2SHELL_COLLECTOR_HOST_LIST[@]}"
        
        while test "$#" -gt 0
        do
            printf  "%s\n"  "${1}"
            
            php2shell_collector_probe   "${1}"
            
        #   to-do: need to test this
            
        #   php2shell_collector_timeout php2shell_collector_probe   "${1}"
            
            shift
            
            sleep   "${PHP2SHELL_COLLECTOR_DELAY}"
        done
        
        
        php2shell_collector_output
        
        printf  "You can find the output for all requested formats at\n"
        printf  "    %s\n"  "${PHP2SHELL_COLLECTOR_OUTPUT}"
    fi
    
    set +x
    
}










# /*!
#   @function   php2shell_collector_timeout
#   
#   @abstract   An almost 'bash-only' timeout replacement (a program in the
#               GNU coreutils package), to allow calling 'php2shell-scan' with
#               a timeout to avoid infinite running.
# */

php2shell_collector_timeout ()
{
    local           pTimeout="${1}"
    local       pGracePeriod="${2}"
    shift 2
    
    local   vCommandID
    local   vTimerID
    local   vResult
    
    "$@" &
    
    vCommandID="$!"
    
#   create and run our watchdog
    
    (
        sleep       "${pTimeout}"
        
    #   request termination of php2shell-scan, if still running
        
        kill -TERM  "${vCommandID}" 2>/dev/null
        
        sleep       "${pGracePeriod}"
        
    #   force termination, if it has not exited
        
        kill -KILL  "${vCommandID}" 2>/dev/null
    ) &
    
    vTimerID="$!"
    
    wait    "${vCommandID}"
    
    vResult="$?"
    
#   stop our watchdog
    
    kill    "${vTimerID}"   2>/dev/null
    wait    "${vTimerID}"   2>/dev/null
    
#     case "${vResult}"
#     in
#     143)
#         :
#     ;;
#     esac
    
    return  "${vResult}"
}










# /*!
#   @function   php2shell_collector_main
#   
#   @abstract   The main function of 'php2shell-collector'. You can also call it
#               within your own shell scripts, by including this file.
# */

php2shell_collector_main ()
{
#   set -x
    
    php2shell_collector_initialize
    
    php2shell_collector_parameters_parse  "$@"
    
#   set +x
    
    php2shell_collector_run
    
}










