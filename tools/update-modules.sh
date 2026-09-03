#!/bin/sh
# Updates the embedded JS modules with the corresponding files in modules/*.js.
# The file changed (in microscript, ILibDuktape_Polyfills.c or ILibDuktape_EmbeddedModules.c)
# depends on which is used.
# Done through update-modules.js, run in a built agent binary by default or under node with -node.
#
# usage: update-modules.sh [-update | -export[=dir] | -list] [-add=name1,name2] [-remove=name1,name2] [-sync] [-dryrun] [-striplegacy] [-binarypath=path | -node]
#
#   -update           update every embedded module whose modules/<name>.js changed. Leaves entries
#                     whose source file is gone in place, and does not add anything new
#   -add=list         comma-separated module names to update, or add as a new entry when a name is
#                     not embedded yet (each needs a matching modules/<name>.js)
#   -remove=list      comma-separated module names to drop from the embedded table, whether or not
#                     modules/<name>.js still exists
#   -sync             in addition to updating, follow modules/ exactly: add any modules/<name>.js
#                     with no entry yet, and remove entries whose modules/<name>.js is gone.
#   -dryrun           only report what would change.
#   -export[=dir]     save the currently embedded scripts, decompressed, into the directory
#                     (default modules_expanded/).
#   -list             print the currently embedded module names and sizes.
#   -binarypath=path  the agent to run in. Default is a built Linux agent in the repository root
#   -node             run under a plain 'node' on PATH instead of an agent binary
#   -striplegacy      moves the embedded modules into ILibDuktape_EmbeddedModules.c: cuts the
#                     addCompressedModule() statements out of ILibDuktape_Polyfills.c and adds a
#                     call to ILibDuktape_Polyfills_EmbeddedModules(ctx) instead.
#

cd "$(dirname "$0")/.." || exit 1

if [ $# -eq 0 ]; then
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

AGENT= ADD= REMOVE= SYNC=0 DRYRUN=0 EXPORT= LIST=0 USE_NODE=0 STRIPLEGACY=0
while [ $# -gt 0 ]; do
    case "$1" in
        -update) ;;
        -list) LIST=1 ;;
        -sync) SYNC=1 ;;
        -dryrun) DRYRUN=1 ;;
        -striplegacy) STRIPLEGACY=1 ;;
        -node) USE_NODE=1 ;;
        -export) EXPORT=modules_expanded ;;
        -export=*) EXPORT="${1#*=}" ;;
        -add=*) ADD="${1#*=}" ;;
        -remove=*) REMOVE="${1#*=}" ;;
        -binarypath=*) AGENT="${1#*=}" ;;
        -add|-remove|-binarypath)
            if [ $# -lt 2 ]; then echo "$1 needs a value" >&2; exit 1; fi
            case "$1" in
                -add) ADD="$2" ;;
                -remove) REMOVE="$2" ;;
                *) AGENT="$2" ;;
            esac
            shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

SCRIPT="var UPDATE_ADD='$ADD'; var UPDATE_REMOVE='$REMOVE'; var UPDATE_SYNC='$SYNC'; var UPDATE_DRYRUN='$DRYRUN'; var UPDATE_EXPORT='$EXPORT'; var UPDATE_LIST='$LIST'; var UPDATE_STRIP_LEGACY='$STRIPLEGACY'; try { eval(require('fs').readFileSync('tools/update-modules.js').toString()); } catch (e) { console.log(e); process.exit(1); } process.exit();"

if [ "$USE_NODE" = "1" ]; then
    [ -n "$AGENT" ] && echo "-node was passed. Ignoring -binarypath $AGENT" >&2
    if ! command -v node >/dev/null 2>&1; then
        echo "-node was passed but node is not on PATH." >&2
        exit 1
    fi
    echo "Using node"
    exec node -e "$SCRIPT"
fi

if [ -n "$AGENT" ]; then
    if [ ! -f "$AGENT" ] || [ ! -x "$AGENT" ]; then
        echo "-binarypath $AGENT is not an executable file" >&2
        exit 1
    fi
else
    for c in meshagent_x86-64 meshagent_x86-64_nokvm meshagent_x86; do
        if [ -x "$c" ]; then AGENT="./$c"; break; fi
    done
    if [ -z "$AGENT" ]; then
        echo "No agent binary found in the repository root. Build one first (make linux ARCHID=6), or pass one with -binarypath." >&2
        exit 1
    fi
fi

if ! command -v base64 >/dev/null 2>&1; then
    echo "base64 is not on PATH, needed to pass the script via -b64exec." >&2
    exit 1
fi

#circumvent 4096 character limit pre-#376 fix
SCRIPT_B64=$(printf '%s' "$SCRIPT" | base64 | tr -d '\n')

echo "Using agent: $AGENT"
exec "$AGENT" -b64exec "$SCRIPT_B64"
