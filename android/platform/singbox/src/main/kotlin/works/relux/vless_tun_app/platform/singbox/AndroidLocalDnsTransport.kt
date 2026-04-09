package works.relux.vless_tun_app.platform.singbox

import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import android.system.ErrnoException
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.UnknownHostException

internal class AndroidLocalDnsTransport(
    private val defaultNetworkMonitor: AndroidDefaultNetworkMonitor,
) : LocalDNSTransport {
    override fun raw(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    override fun exchange(
        ctx: ExchangeContext,
        message: ByteArray,
    ) {
        runBlocking {
            val network = requireUnderlyingNetwork()
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                error("Raw DNS exchange requires Android Q or newer.")
            }
            suspendCoroutine { continuation ->
                val signal = CancellationSignal()
                ctx.onCancel(signal::cancel)
                DnsResolver.getInstance().rawQuery(
                    network,
                    message,
                    DnsResolver.FLAG_NO_RETRY,
                    Dispatchers.IO.asExecutor(),
                    signal,
                    object : DnsResolver.Callback<ByteArray> {
                        override fun onAnswer(
                            answer: ByteArray,
                            rcode: Int,
                        ) {
                            if (rcode == 0) {
                                ctx.rawSuccess(answer)
                            } else {
                                ctx.errorCode(rcode)
                            }
                            continuation.resume(Unit)
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            val cause = error.cause
                            if (cause is ErrnoException) {
                                ctx.errnoCode(cause.errno)
                                continuation.resume(Unit)
                                return
                            }
                            ctx.errorCode(RCODE_SERVFAIL)
                            continuation.resume(Unit)
                        }
                    },
                )
            }
        }
    }

    override fun lookup(
        ctx: ExchangeContext,
        network: String,
        domain: String,
    ) {
        runBlocking {
            val underlyingNetwork = requireUnderlyingNetwork()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                suspendCoroutine { continuation ->
                    val signal = CancellationSignal()
                    ctx.onCancel(signal::cancel)
                    val callback = object : DnsResolver.Callback<Collection<InetAddress>> {
                        override fun onAnswer(
                            answer: Collection<InetAddress>,
                            rcode: Int,
                        ) {
                            if (rcode == 0) {
                                ctx.success(
                                    answer
                                        .mapNotNull(InetAddress::getHostAddress)
                                        .joinToString("\n"),
                                )
                            } else {
                                ctx.errorCode(rcode)
                            }
                            continuation.resume(Unit)
                        }

                        override fun onError(error: DnsResolver.DnsException) {
                            val cause = error.cause
                            if (cause is ErrnoException) {
                                ctx.errnoCode(cause.errno)
                                continuation.resume(Unit)
                                return
                            }
                            ctx.errorCode(RCODE_SERVFAIL)
                            continuation.resume(Unit)
                        }
                    }
                    val queryType = when {
                        network.endsWith("4") -> DnsResolver.TYPE_A
                        network.endsWith("6") -> DnsResolver.TYPE_AAAA
                        else -> null
                    }
                    if (queryType != null) {
                        DnsResolver.getInstance().query(
                            underlyingNetwork,
                            domain,
                            queryType,
                            DnsResolver.FLAG_NO_RETRY,
                            Dispatchers.IO.asExecutor(),
                            signal,
                            callback,
                        )
                    } else {
                        DnsResolver.getInstance().query(
                            underlyingNetwork,
                            domain,
                            DnsResolver.FLAG_NO_RETRY,
                            Dispatchers.IO.asExecutor(),
                            signal,
                            callback,
                        )
                    }
                }
            } else {
                try {
                    val answer = underlyingNetwork.getAllByName(domain)
                    ctx.success(
                        answer.mapNotNull(InetAddress::getHostAddress).joinToString("\n"),
                    )
                } catch (_: UnknownHostException) {
                    ctx.errorCode(RCODE_NXDOMAIN)
                }
            }
        }
    }

    private fun requireUnderlyingNetwork(): Network {
        return defaultNetworkMonitor.require()
    }

    private companion object {
        const val RCODE_NXDOMAIN = 3
        const val RCODE_SERVFAIL = 2
    }
}
