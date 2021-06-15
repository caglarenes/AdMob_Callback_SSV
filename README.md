# AdMob_Callback_SSV
An example ASP.NET 6 (Preview 4 with Minimal API) web server for use to verify AdMob Rewarded Ad callback system named SSV (Server Side Verification)

Listening :88 for HTTP and :444 for HTTPS because you may want to create another ASP.NET instance to your domain for to serve default website requests.

# Usage
You can create an "Rewarded Ad" and enable "Server Side Verification" for it at AdMob Console.
</br>
In test screen, you can call your server like https://www.YOURWEBSITE:444/ to try and verify callback URL.
</br>
Don't forget the fill "user_id" parameter.
