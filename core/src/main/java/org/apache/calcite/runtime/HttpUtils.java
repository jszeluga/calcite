/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.calcite.runtime;

import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Map;
import java.util.function.Function;

/**
 * Utilities for connecting to REST services such as Splunk via HTTP.
 */
public class HttpUtils {
  private HttpUtils() {}

  public static void appendURLEncodedArgs(
      StringBuilder out, Map<String, String> args) {
    int i = 0;
    try {
      for (Map.Entry<String, String> me : args.entrySet()) {
        if (i++ != 0) {
          out.append("&");
        }
        out.append(URLEncoder.encode(me.getKey(), "UTF-8"))
            .append("=")
            .append(URLEncoder.encode(me.getValue(), "UTF-8"));
      }
    } catch (UnsupportedEncodingException ignore) {
      // ignore
    }
  }

  public static void appendURLEncodedArgs(
      StringBuilder out, CharSequence... args) {
    if (args.length % 2 != 0) {
      throw new IllegalArgumentException(
          "args should contain an even number of items");
    }
    try {
      int appended = 0;
      for (int i = 0; i < args.length; i += 2) {
        if (args[i + 1] == null) {
          continue;
        }
        if (appended++ > 0) {
          out.append("&");
        }
        out.append(URLEncoder.encode(args[i].toString(), "UTF-8"))
            .append("=")
            .append(URLEncoder.encode(args[i + 1].toString(), "UTF-8"));
      }
    } catch (UnsupportedEncodingException ignore) {
      // ignore
    }
  }

  public static <R> R post(
      String url,
      CharSequence data,
      Map<String, String> headers,
      Function<InputStream, R> responseCallback) throws IOException {
    return post(url, data, headers, responseCallback, 10000, 60000);
  }

  public static <R> R post(
      String url,
      CharSequence data,
      Map<String, String> headers,
      Function<InputStream, R> responseCallback,
      int cTimeout,
      int rTimeout) throws IOException {
    return executeMethod(url, data, headers, responseCallback,
        cTimeout, rTimeout);
  }

  public static <R> R executeMethod(
      String url,
      CharSequence data, Map<String, String> headers, Function<InputStream, R> responseCallback,
      int cTimeout, int rTimeout) throws IOException {
    // NOTE: do not log "data" or "url"; may contain user name or password.

    //Kerberos
    boolean isKerberos = System.getProperty("java.security.auth.login.config") != null
        && System.getProperty("java.security.krb5.conf") != null;

    RequestConfig requestConfig = RequestConfig.custom()
        .setConnectTimeout(cTimeout)
        .setSocketTimeout(rTimeout).build();

    //if SSL is being used just use it for communication. No need to check the certificate
    try (CloseableHttpClient httpClient = HttpClients.custom()
        .setDefaultRequestConfig(requestConfig)
        .setSSLSocketFactory(
            new SSLConnectionSocketFactory(TrustAllSslSocketFactory.createSSLSocketFactory(),
                (s, sslSession) -> true))
        .build()) {

      HttpRequestBase request;

      if (data == null) {
        //GET
        request = new HttpGet(url);

      } else {
        //POST
        HttpPost post = new HttpPost(url);
        post.setEntity(new StringEntity(data.toString(), StandardCharsets.UTF_8));

        request = post;
      }

      if (headers != null) {
        headers.forEach(request::setHeader);
      }


      CloseableHttpResponse httpResponse;

      if (isKerberos) {
        //Authenticate with Kerberos Keytab
        Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
            .register(AuthSchemes.SPNEGO, new SPNegoSchemeFactory(true)).build();

        HttpClientContext clientContext = HttpClientContext.create();
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();

        credentialsProvider.setCredentials(AuthScope.ANY, new Credentials() {
          public Principal getUserPrincipal() {
            return null;
          }

          public String getPassword() {
            return null;
          }
        });

        clientContext.setCredentialsProvider(credentialsProvider);
        clientContext.setAuthSchemeRegistry(authSchemeRegistry);

        httpResponse = httpClient.execute(request, clientContext);
      } else {
        httpResponse = httpClient.execute(request);
      }

      int statusCode = httpResponse.getStatusLine().getStatusCode();
      if (statusCode == HttpStatus.SC_OK) {
        //If response is 200 then pass the InputStream to the callback
        //InputStream is AutoClosed with try resource management
        try (InputStream inputStream = httpResponse.getEntity().getContent()) {
          return responseCallback.apply(inputStream);
        }
      } else {
        String errorResponse = EntityUtils.toString(httpResponse.getEntity());
        throw new IOException("HTTP status code: " + statusCode
            + " Error Message: " + errorResponse);
      }

    }

  }
}

// End HttpUtils.java
