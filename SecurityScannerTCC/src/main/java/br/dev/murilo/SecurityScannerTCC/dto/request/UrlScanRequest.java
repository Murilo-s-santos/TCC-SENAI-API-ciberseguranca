package br.dev.murilo.SecurityScannerTCC.dto.request;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;

public record UrlScanRequest
(
    @NotBlank(message = "A URL não pode estar vazia.")
    @URL(message = "O formato da URL enviada é inválido.")
    String url
) {}
