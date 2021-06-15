using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
await using var app = builder.Build();

//Cache AdMob Keys for performance
Dictionary<string, AdmobKey> admobKeys = new();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.MapGet("/", async httpContext =>
{
    //await httpContext.Response.WriteAsync("Hello World!");
    Console.WriteLine($"Incoming Request Parameters: {httpContext.Request.QueryString.Value}");

    //Check incoming callback parameter rules at https://developers.google.com/admob/unity/ssv#ssv_callback_parameters

    if (!httpContext.Request.Query.TryGetValue("user_id", out var userID))
    {
        //It's not necessary but useful for server side
        httpContext.Response.StatusCode = 400;
        await httpContext.Response.CompleteAsync();
        return;
    }

    if (String.IsNullOrWhiteSpace(userID))
    {
        //user_id can be sent empty from Google. Prevent errors.
        httpContext.Response.StatusCode = 400;
        await httpContext.Response.CompleteAsync();
        return;
    }

    if (!httpContext.Request.Query.TryGetValue("signature", out var signatureID))
    {
        //Signature is important for verify message
        httpContext.Response.StatusCode = 400;
        await httpContext.Response.CompleteAsync();
        return;
    }

    if (!httpContext.Request.Query.TryGetValue("key_id", out var keyID))
    {
        //Key ID should match with AdMob provided key id's.
        httpContext.Response.StatusCode = 400;
        await httpContext.Response.CompleteAsync();
        return;
    }

    if (String.IsNullOrWhiteSpace(keyID))
    {
        //Key ID should be not null
        httpContext.Response.StatusCode = 400;
        await httpContext.Response.CompleteAsync();
        return;
    }

    //Verify Token for security
    if (VerifyToken(httpContext.Request.QueryString.Value, userID, signatureID, keyID))
    {
        //Another nice place to Server Side Jobs
        httpContext.Response.StatusCode = 200;
        await httpContext.Response.CompleteAsync();
    }
    else
    {
        //Wrong Informations. Maybe a hack attempt.
        httpContext.Response.StatusCode = 401;
        await httpContext.Response.CompleteAsync();
    }
});

//Take AdMob Public keys at start-up. Don't need to await for server start-up.
CachePublicKey();

//Start Server
await app.RunAsync();



async Task CachePublicKey()
{
    // AdMob public keys changing time-to-time. They suggest to reflesh cache at least in 24-hour

    while (true)
    {
        GetPublicKeysAsync();
        //12 Hours in milisecond
        await Task.Delay(43200000);
    }
}

async Task GetPublicKeysAsync()
{
    var client = new HttpClient();

    string jsontext = await client.GetStringAsync("https://www.gstatic.com/admob/reward/verifier-keys.json");
    Console.WriteLine("Response Json: " + jsontext);

    //Deserialise JSON DATA. There is no offical map document for JSON deserializing. So doing it by hand. 
    JsonDocument document = JsonDocument.Parse(jsontext);
    JsonElement root = document.RootElement;
    JsonElement keysArrayJSON = root.GetProperty("keys");
    Console.WriteLine("Keys Array Lenght: " + keysArrayJSON.GetArrayLength());

    //!PREVENT RACE CONDITION. ASP.NET app maybe using old keys for response GET requests at the time.
    //? Maybe complete stop app or minimal Delay for while?
    lock (admobKeys)
    {
        admobKeys.Clear();
        foreach (var item in keysArrayJSON.EnumerateArray())
        {
            JsonElement keyIDJSON = item.GetProperty("keyId");
            JsonElement pemJSON = item.GetProperty("pem");
            JsonElement base64JSON = item.GetProperty("base64");

            AdmobKey newKey = new(keyIDJSON.GetUInt64().ToString(), pemJSON.GetString(), base64JSON.GetString());
            admobKeys.Add(newKey.keyID, newKey);
        }
    }
}

bool VerifyToken(string gelecekYazi, string kullaniciID, string signatureID, string keyID)
{
    Console.WriteLine("Verifying user request...");

    string queryString = gelecekYazi.Substring(1, gelecekYazi.IndexOf("signature=") - 2);

    byte[] queryStringByte = Encoding.UTF8.GetBytes(queryString);

    if (!admobKeys.TryGetValue(keyID, out var foundKey))
    {
        Console.WriteLine("Key ID can't found!");
        return false;
    }

    if (foundKey.certificate.VerifyData(queryStringByte, Base64URLSafeConverter(signatureID), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
    {
        Console.WriteLine("Key is absolutely true :)");

        //TODO Server Side Jobs...

        return true;
    }
    else
    {
        Console.WriteLine("Key was wrong :(");
        return false;
    }
}


static byte[] Base64URLSafeConverter(string safeURL)
{
    //BASE64 is not URL safe normally. Google probably changes it to BASE64URL - a safe version. So we should revert it to original.
    // source: https://stackoverflow.com/questions/26353710/how-to-achieve-base64-url-safe-encoding-in-c

    string incoming = safeURL.Replace('_', '/').Replace('-', '+');
    switch (safeURL.Length % 4)
    {
        case 2: incoming += "=="; break;
        case 3: incoming += "="; break;
    }

    byte[] bytes = Convert.FromBase64String(incoming);
    return bytes;
}

class AdmobKey
{
    public string keyID;
    public string pem;
    public string base64;

    public byte[] base64ByteArray;

    public ECDsa certificate;

    public AdmobKey(string keyID, string pem, string base64)
    {
        this.keyID = keyID;
        this.pem = pem;
        this.base64 = base64;
        this.base64ByteArray = Convert.FromBase64String(base64);

        CreateCertificate();
    }
    public void CreateCertificate()
    {
        // ECDsa Interface using ECDsaCng for Windows and ECDsaOpenSsl for Linux because these libraries don't support for other OS'es.

        certificate = ECDsa.Create();
        certificate.ImportSubjectPublicKeyInfo(base64ByteArray, out _);
    }

}