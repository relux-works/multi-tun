package works.relux.vless_tun_app.core.mvi

import kotlinx.coroutines.flow.StateFlow

interface MviStore<State, Action> {
    val state: StateFlow<State>

    fun dispatch(action: Action)
}
