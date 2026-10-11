package com.example.mbff;

import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/** Shell 인증서버(티켓 검증). 티켓은 1회용이며 검증 시 소진된다. */
@Component
public class ShellTicketClient {
    public record Verified(String username, String deviceId) {}

    private final WebClient http = WebClient.create();
    private final MobileBffProperties props;

    public ShellTicketClient(MobileBffProperties props) { this.props = props; }

    @SuppressWarnings("unchecked")
    public Mono<Verified> verify(String ticket, String deviceId) {
        return http.post().uri(props.shell().verifyUrl())
                .header("X-Api-Key", props.shell().apiKey())
                .bodyValue(Map.of("ticket", ticket, "spa", props.spaId(),
                        "device_id", deviceId == null ? "" : deviceId))
                .retrieve().bodyToMono(Map.class)
                .map(m -> new Verified((String) m.get("username"), (String) m.get("device_id")));
    }
}
