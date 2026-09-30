package br.dev.murilo.SecurityScannerTCC.controller;

import br.dev.murilo.SecurityScannerTCC.dto.request.UrlScanRequest;
import br.dev.murilo.SecurityScannerTCC.dto.response.UrlScanResponse;
import br.dev.murilo.SecurityScannerTCC.service.VirusTotalService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/scans")
@CrossOrigin(origins = "*") // Permite requisições do front-end (React, Vue, HTML puro, etc.)
public class UrlScanController {

    private final VirusTotalService virusTotalService;

    public UrlScanController(VirusTotalService virusTotalService) {
        this.virusTotalService = virusTotalService;
    }

    @PostMapping("/url")
    public ResponseEntity<UrlScanResponse> escanearUrl(@Valid @RequestBody UrlScanRequest request) {
        UrlScanResponse resultado = virusTotalService.analisarUrl(request.url());
        return ResponseEntity.ok(resultado);
    }
}