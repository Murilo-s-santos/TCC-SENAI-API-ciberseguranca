package br.dev.murilo.SecurityScannerTCC.service;

import br.dev.murilo.SecurityScannerTCC.dto.response.UrlScanResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Service
public class VirusTotalService {

    private final RestClient restClient;

    public VirusTotalService(
            @Value("${virustotal.api.url}") String baseUrl,
            @Value("${virustotal.api.key}") String apiKey) {
        
        // Inicializa a ferramenta de requisições HTTP do Spring Boot 3
        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("x-apikey", apiKey)
                .build();
    }

    public UrlScanResponse analisarUrl(String targetUrl) {
        // O VirusTotal v3 exige que a URL seja convertida para Base64 sem preenchimento (=)
        String urlId = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(targetUrl.getBytes(StandardCharsets.UTF_8));

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = restClient.get()
                    .uri("/urls/{id}", urlId)
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, (req, resp) -> {
                        if (resp.getStatusCode().value() == 404) {
                            throw new RuntimeException("A URL informada ainda não consta na base do VirusTotal.");
                        }
                        throw new RuntimeException("Falha na requisição para o servidor de segurança.");
                    })
                    .body(Map.class);

            return processarRespostaVirusTotal(targetUrl, response);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao processar análise de URL: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private UrlScanResponse processarRespostaVirusTotal(String targetUrl, Map<String, Object> rawJson) {
        // Navegação pelo JSON do VirusTotal: data -> attributes -> last_analysis_stats
        Map<String, Object> data = (Map<String, Object>) rawJson.get("data");
        Map<String, Object> attributes = (Map<String, Object>) data.get("attributes");
        Map<String, Object> stats = (Map<String, Object>) attributes.get("last_analysis_stats");

        int malicious = (int) stats.getOrDefault("malicious", 0);
        int suspicious = (int) stats.getOrDefault("suspicious", 0);
        int harmless = (int) stats.getOrDefault("harmless", 0);
        int undetected = (int) stats.getOrDefault("undetected", 0);

        int totalEngines = malicious + suspicious + harmless + undetected;
        int ameacas = malicious + suspicious;

        // Regra de Negócio para o Score (0 a 100)
        int score = 0;
        if (totalEngines > 0) {
            score = (int) (((double) ameacas / totalEngines) * 100);
        }

        // Definição do Status
        String status = "SEGURO";
        if (score >= 5) {
            status = "PERIGOSO";
        } else if (score > 2) {
            status = "SUSPEITO";
        }

        String mensagem = String.format("%d de %d motores de análise detectaram ameaças.", ameacas, totalEngines);

        return new UrlScanResponse(targetUrl, status, score, ameacas, totalEngines, mensagem);
    }
}
