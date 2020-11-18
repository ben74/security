-  Alpow Security tools and functions !
---
- Copy and paste this in order to use as simple firewall :
 
        if(isset($_SERVER['REQUEST_URI'])){
             require_once'vendor/autoload.php';use Alpow\Security\Security;
             $isblocked=Security::blockMaliciousRequests();
             Security::r404($isblocked);
             #Security::dbM($isblocked,'blocked','secu.log');#append to optional log file or send it to bus / logCollector
         }
---
![visitors](https://visitor-badge.glitch.me/badge?page_id=gh:ben74:alpow:security)
