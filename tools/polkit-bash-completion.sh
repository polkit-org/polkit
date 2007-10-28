
####################################################################################################

__polkit_auth() {
    local IFS=$'\n'
    local cur="${COMP_WORDS[COMP_CWORD]}"

    case $COMP_CWORD in
        1)
            COMPREPLY=($(IFS=: compgen -S' ' -W "--obtain:--show-obtainable:--explicit:--explicit-detail:--grant:--revoke:--user:--version:--help" -- $cur))
            ;;
        2)
	    case "${COMP_WORDS[1]}" in
                --obtain)   
                    COMPREPLY=($(compgen -W "$(polkit-auth --show-obtainable)" -- $cur))
                    ;;
                --revoke) 
                    COMPREPLY=($(compgen -W "$(polkit-auth --explicit)" -- $cur))
                    ;;
                --grant) 
                    COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                    ;;
                --user)   
                    COMPREPLY=($(compgen -u -- $cur))
                    ;;
            esac
            ;;
        3)
	    case "${COMP_WORDS[1]}" in
                --user)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--explicit:--explicit-detail:--grant:--revoke" -- $cur))
                    ;;
                --grant)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--constraint" -- $cur))
                    ;;
            esac
            ;;
        4)
	    case "${COMP_WORDS[3]}" in
                --revoke) 
	            case "${COMP_WORDS[1]}" in
                        --user)
                            local afou
                            # we may not be authorized to read the explicit auths for the given user..
                            afou=$(polkit-auth --user ${COMP_WORDS[2]} --explicit 2> /dev/null) 
                            if [ $? != 0 ] ; then
                                # .. so if that fails, fall back to showing all actions
                                afou=$(polkit-action)
                            fi
                            COMPREPLY=($(compgen -W "$afou" -- $cur))
                            ;;
                        *)
                            COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                            ;;
                    esac
                    ;;
                --grant)
                    COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                    ;;
                --constraint)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "none:local:active:local+active" -- $cur))
                    ;;
            esac
            ;;
        5)
	    case "${COMP_WORDS[3]}" in
                --grant)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--constraint" -- $cur))
                    ;;
            esac
            ;;
        6)
	    case "${COMP_WORDS[5]}" in
                --constraint)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "none:local:active:local+active" -- $cur))
                    ;;
            esac
            ;;
    esac
}

####################################################################################################

__polkit_action() {
    local IFS=$'\n'
    local cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD = 1 ]; then
        COMPREPLY=($(IFS=: compgen -S' ' -W "--action:--version:--help" -- $cur))
    else
	case "${COMP_WORDS[1]}" in
            --action) 
                COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                ;;
        esac
    fi
}

####################################################################################################

complete -o nospace -F __polkit_auth polkit-auth
complete -o nospace -F __polkit_action polkit-action
