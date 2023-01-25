package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.codec.json.Jackson2JsonDecoder;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;

import static org.springframework.security.oauth2.client.OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME;
import static org.springframework.security.oauth2.client.OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

public class Main {
    public static void main(String[] args) throws IOException {

        var credentials = Map.of(
                "one", Map.of("username", "x$19a#6j41pp", "password", "Si2j#$Ib9L"),
                "two", Map.of("username", "x$19a#6j41pp", "password", "Si2j#$Ib9L")
        );

        var oneRegistration = ClientRegistration
                .withRegistrationId("logo")
                .tokenUri("https://domain/services/oauth2/token")
                .clientId("3MVG9FS3Iyro")
                .clientSecret("126210003")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .build();

        var twoRegistration = ClientRegistration
                .withRegistrationId("orderStatus")
                .tokenUri("https://domain/services/oauth2/token")
                .clientId("3MVG9FS3IyroMOh6FIxDte")
                .clientSecret("1868619363")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .build();

        var registrationRepository = new InMemoryReactiveClientRegistrationRepository(oneRegistration, twoRegistration);
        var authorizedClientService = new InMemoryReactiveOAuth2AuthorizedClientService(registrationRepository);
        var authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                .password()
                .refreshToken()
                .build();

        var authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
                registrationRepository, authorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        authorizedClientManager.setContextAttributesMapper(contextAttributesMapper(credentials));

        var sslContext = SslContextBuilder
                .forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        var httpClient = HttpClient.create(ConnectionProvider.newConnection())
                .secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));

        var oauth = new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

        var webClient = WebClient.builder()
                .filter(oauth)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .codecs(clientDefaultCodecsConfigurer -> {
                    clientDefaultCodecsConfigurer.defaultCodecs().jackson2JsonEncoder(new Jackson2JsonEncoder(new ObjectMapper(), MediaType.APPLICATION_JSON));
                    clientDefaultCodecsConfigurer.defaultCodecs().jackson2JsonDecoder(new Jackson2JsonDecoder(new ObjectMapper(), MediaType.APPLICATION_JSON));
                })
                .build();

        var oneMono = webClient.post()
                .uri("https://domain/services/apexrest/one")
                .attributes(clientRegistrationId("one"))
                .retrieve()
                .bodyToMono(String.class);

        System.out.println(oneMono.block());

        System.out.println("---------------------------------------------");

        var twoMono = webClient.post()
                .uri("https://domain/services/apexrest/two")
                .attributes(clientRegistrationId("two"))
                .retrieve()
                .bodyToMono(String.class);

        System.out.println(twoMono.block());
    }

    private static Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper(Map<String, Map<String, String>> credentials) {
        return authorizeRequest -> {
            var usernameAndPassword = credentials.get(authorizeRequest.getClientRegistrationId());
            return Mono.just(Map.of(USERNAME_ATTRIBUTE_NAME, usernameAndPassword.get("username"),
                    PASSWORD_ATTRIBUTE_NAME, usernameAndPassword.get("password")));
        };
    }
}