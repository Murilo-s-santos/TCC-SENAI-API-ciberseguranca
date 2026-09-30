package br.dev.murilo.SecurityScannerTCC.dto.response;

public record UrlScanResponse
(
    String urlAnalisada,
    String status, // SEGURO, SUSPEITO, PERIGOSO
    int pontuacaoRisco, // 0 a 100
    int motoresAmeaca, // Qtd de antivirus que detectaram perigo
    int totalMotores, // Total de antivírus consultados
    String mensagemResumo        
){}
