import * as fs from "fs"
import path from "path";

const name = "Sniffing Ferret"
const tagline = "Sniffing out the secrets before the leakout"
const currentDirectoryPath = process.cwd()
const nameVar = name.split(" ").join("_");

const metaData = `${name} is developed by Sahil Sharma \nGithub: www.github.com/sahil75831 \nLinkedin: www.linkedin.com/in/sahil-sharma-ss9043283 \nMedium: https://medium.com/@sahilsharma_SoftwareDeveloper \n\n`

const patternFileContent = {
  // AWS (Amazon Web Services)
  AWS_ACCESS: "^(AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}$",
  AWS_SECRET_ACCESS_KEY: "^(?![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])$",
  AWS_SESSION_TOKEN: "^FQoGZXIv[A-Za-z0-9+/=]{200,}$",
  AWS_MWS_AUTH_TOKEN: "^amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
  AWS_LAMBDA_KEY: "^[a-zA-Z0-9_/+=]{40}$",

  // Google Cloud Platform (GCP)
  GCP_API_KEY: "^AIza[0-9A-Za-z\\-_]{35}$",
  GCP_SERVICE_ACCOUNT_KEY: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
  GCP_OAUTH_TOKEN: "^ya29\\.[0-9A-Za-z\\-_]+$",
  GCP_CLOUD_FUNCTION_KEY: "^[0-9a-zA-Z\\-_]{40,}$",
  GCP_STORAGE_BUCKET_CRED: "^[0-9a-zA-Z\\-_]{32,}$",

  // Microsoft Azure
  AZURE_CLIENT_ID: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
  AZURE_CLIENT_SECRET: "^[0-9a-zA-Z\\-_]{30,50}$",
  AZURE_DEVOPS_PAT: "^[a-z0-9]{52}$",
  AZURE_STORAGE_KEY: "^[A-Za-z0-9+/=]{88}$",
  AZURE_COSMOSDB_KEY: "^[A-Za-z0-9+/=]{88}$",

  // JSON Web Tokens (JWT)
  JWT: "^[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]{2,}$",

  // Stripe (Payments)
  STRIPE_API_KEY: "^(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}$",
  STRIPE_WEBHOOK_SECRET: "^whsec_[a-zA-Z0-9]{24,}$",
  STRIPE_RESTRICTED_KEY: "^rk_(test|live)_[0-9a-zA-Z]{24,}$",

  // Slack
  SLACK_TOKEN: "^xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32}$",
  SLACK_WEBHOOK: "^https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}$",
  SLACK_BOT_TOKEN: "^xoxb-[0-9]{12}-[0-9]{12}-[a-f0-9]{24}$",

  // GitHub
  GITHUB_PAT: "^(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}$",
  GITHUB_FINE_GRAINED_PAT: "^github_pat_[0-9a-zA-Z_]{82}$",
  GITHUB_OAUTH_TOKEN: "^gho_[0-9a-zA-Z]{36}$",
  GITHUB_APP_TOKEN: "^ghu_[0-9a-zA-Z]{36}$",

  // Twilio (SMS & Voice API)
  TWILIO_API_KEY: "^SK[0-9a-fA-F]{32}$",
  TWILIO_ACCOUNT_SID: "^AC[a-fA-F0-9]{32}$",
  TWILIO_AUTH_TOKEN: "^[0-9a-fA-F]{32}$",

  // Mailchimp (Email Marketing)
  MAILCHIMP_API_KEY: "^[a-f0-9]{32}-us[0-9]{1,2}$",

  // Heroku (Cloud Platform)
  HEROKU_API_KEY: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",

  // DigitalOcean (Cloud Hosting)
  DIGITALOCEAN_TOKEN: "^dop_v1_[a-f0-9]{64}$",
  DIGITALOCEAN_SPACES_KEY: "^[a-f0-9]{16}$",
  DIGITALOCEAN_SPACES_SECRET: "^[a-f0-9]{40}$",

  // Firebase (Google’s Mobile Platform)
  FIREBASE_API_KEY: "^AIza[0-9A-Za-z\\-_]{35}$",
  FIREBASE_CLOUD_MESSAGING_KEY: "^AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}$",
  FIREBASE_AUTH_TOKEN: "^[0-9a-zA-Z\\-_]{100,}$",

  // MongoDB (Database)
  MONGODB_URI: "^mongodb(\\+srv)?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+(/[a-zA-Z0-9._-]+)?$",

  // PostgreSQL (Database)
  POSTGRESQL_URL: "^postgres(ql)?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+(/[a-zA-Z0-9._-]+)?$",

  // SendGrid (Email API)
  SENDGRID_API_KEY: "^SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}$",

  // PayPal (Payments)
  PAYPAL_CLIENT_ID: "^[A-Za-z0-9_-]{80}$",
  PAYPAL_SECRET: "^[A-Za-z0-9_-]{80}$",

  // OpenAI (AI API)
  OPENAI_API_KEY: "^sk-[a-zA-Z0-9]{32,64}$",
  OPENAI_ORG_ID: "^org-[a-zA-Z0-9]{24}$",

  // Fastly (CDN)
  FASTLY_API_KEY: "^[a-zA-Z0-9_-]{32}$",

  // Datadog (Monitoring)
  DATADOG_API_KEY: "^[a-f0-9]{32}$",
  DATADOG_APP_KEY: "^[a-f0-9]{40}$",

  // Alibaba Cloud
  ALIBABA_ACCESS_KEY_ID: "^LTAI[a-zA-Z0-9]{16,32}$",
  ALIBABA_SECRET_KEY: "^[a-zA-Z0-9]{30}$",

  // Cloudflare (CDN & Security)
  CLOUDFLARE_API_KEY: "^[a-f0-9]{37}$",
  CLOUDFLARE_GLOBAL_API_KEY: "^[a-f0-9]{40}$",
  CLOUDFLARE_CA_KEY: "^[a-f0-9]{32}$",

  // Docker (Container Registry)
  DOCKER_REGISTRY_AUTH: "^[a-zA-Z0-9+/=]{100,}$",
  DOCKER_HUB_TOKEN: "^dckr_pat_[a-zA-Z0-9_-]{27}$",

  // NPM (Node Package Manager)
  NPM_TOKEN: "^npm_[a-zA-Z0-9]{36}$",

  // Square (Payments)
  SQUARE_ACCESS_TOKEN: "^sq0atp-[a-zA-Z0-9_-]{22,32}$",
  SQUARE_SECRET: "^sq0csp-[a-zA-Z0-9_-]{43,}$",

  // Dropbox (File Storage)
  DROPBOX_ACCESS_TOKEN: "^sl\\.[a-zA-Z0-9_-]{135}$",
  DROPBOX_SHORT_LIVED_TOKEN: "^sl\\.[a-zA-Z0-9_-]{64}$",

  // Zoom (Video Conferencing)
  ZOOM_API_KEY: "^[a-zA-Z0-9_-]{32}$",
  ZOOM_JWT_TOKEN: "^eyJ[0-9a-zA-Z_-]{10,}\\.eyJ[0-9a-zA-Z_-]{10,}\\.[0-9a-zA-Z_-]{10,}$",

  // Bitbucket (Git Hosting)
  BITBUCKET_CLIENT_ID: "^[a-zA-Z0-9_-]{32}$",
  BITBUCKET_CLIENT_SECRET: "^[a-zA-Z0-9_-]{64}$",
  BITBUCKET_APP_PASSWORD: "^[0-9a-zA-Z]{20}$",

  // GitLab (DevOps Platform)
  GITLAB_PAT: "^glpat-[a-zA-Z0-9_-]{20}$",
  GITLAB_OAUTH_TOKEN: "^[0-9a-zA-Z_-]{64}$",

  // New Relic (Monitoring)
  NEW_RELIC_API_KEY: "^[a-f0-9]{36}NRAL$",
  NEW_RELIC_LICENSE_KEY: "^[a-f0-9]{40}$",

  // Travis CI (Continuous Integration)
  TRAVIS_CI_TOKEN: "^[a-f0-9]{22}$",

  // Kubernetes (Container Orchestration)
  KUBERNETES_SERVICE_ACCOUNT_TOKEN: "^eyJ[0-9a-zA-Z_-]{10,}\\.eyJ[0-9a-zA-Z_-]{10,}\\.[0-9a-zA-Z_-]{10,}$",

  // Additional Services
  ATLASSIAN_API_TOKEN: "^AT[0-9a-zA-Z]{24}$",
  AUTH0_CLIENT_ID: "^[0-9a-zA-Z]{32}$",
  AUTH0_CLIENT_SECRET: "^[0-9a-zA-Z\\-_]{48}$",
  SHOPIFY_ACCESS_TOKEN: "^shpat_[0-9a-fA-F]{32}$",
  SHOPIFY_API_SECRET: "^shpss_[0-9a-fA-F]{32}$",
  OKTA_API_TOKEN: "^[0-9a-zA-Z]{42}$",
  ALGOLIA_API_KEY: "^[0-9a-fA-F]{32}$",
  ALGOLIA_ADMIN_API_KEY: "^[0-9a-fA-F]{32}$",
  NETLIFY_API_TOKEN: "^[0-9a-zA-Z]{40,}$",
  VERCEL_TOKEN: "^[0-9a-zA-Z]{24}$",
  CIRCLECI_TOKEN: "^[0-9a-fA-F]{40}$",
  SENTRY_AUTH_TOKEN: "^[0-9a-fA-F]{64}$",
  HUBSPOT_API_KEY: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
  PAGERDUTY_API_TOKEN: "^[a-zA-Z0-9_-]{20}$",
  REDIS_URL: "^redis://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+:[0-9]+(/[0-9])?$",
  MYSQL_URL: "^mysql://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9.-]+(/[a-zA-Z0-9._-]+)?$",
  STRAPI_API_TOKEN: "^[0-9a-fA-F]{64}$",
  SALESFORCE_CLIENT_ID: "^[0-9a-zA-Z]{60}$",
  SALESFORCE_CLIENT_SECRET: "^[0-9a-zA-Z]{60}$",
  JENKINS_API_TOKEN: "^[0-9a-fA-F]{40}$",
  HASHICORP_VAULT_TOKEN: "^[hvs]\\.[0-9a-zA-Z]{24}$",
  AIRTABLE_API_KEY: "^key[a-zA-Z0-9]{14}$",
  CONTENTFUL_ACCESS_TOKEN: "^[0-9a-zA-Z_-]{64}$",
  NETDATA_BEARER_TOKEN: "^Bearer\\s[0-9a-zA-Z\\-_]{36,}$",
  INTERCOM_API_KEY: "^[0-9a-zA-Z_-]{60}$",
  ZAPIER_WEBHOOK: "^https://hooks.zapier.com/hooks/catch/[0-9a-zA-Z]+/[0-9a-zA-Z]+$",
  DYNATRACE_API_TOKEN: "^dt0[a-zA-Z0-9]{24}\\.[0-9a-zA-Z]{16}\\.[0-9a-zA-Z]{64}$",
  GRAFANA_API_KEY: "^eyJr[a-zA-Z0-9+/=]{100,}$",
  LINODE_API_TOKEN: "^[0-9a-zA-Z]{64}$",
  GENERIC_API_KEY: "^[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]$",
  GENERIC_SECRET: "^[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]$"
};

const asciiART = `                                                                                                                                                                                                                                                                        
                                                                                                                                              
            =*##+-                                    -+*#*-                                                                                          
          :#%####%#-                                =######%+                                                                                         
         .%######**%*        .:=+*#####*+-:.      :##**#####%+                                                                                        
         %#########*#%.   .*@%#**********#%%%=.  -%***#######%:                                                                                       
        =%###%##%%*#*#%:=%#*++++++++++*+++++*#%#+#+####%**%###%                                                                                       
        %####====*%##*%%#*+**++++**++++++++++++*%#*##%*=--=####:                                                                                      
       :%##%=---==+%#%#*++++++++++++++++++++++****%#%*=-=--+%###                                                                                      
       =%##*--=-===#%*++++*+*+*++++++++++++++++**+*#%====---###%.                                                                                     
       *##%+---=+=##**++++*++*+++++++++++++++*+++++*##==+==-*##%:                                                                                     
       ###%=--=+=#%*++++*++++++++++++++++++++*+++*+++##====-+##%-                                                                                     
       ###%=-=+=*#++-.   -+*+*++++++++++++++*=. ..=***%*+==-+##%-                                                                                     
       *%#%=-==+%*-...... .:*+*+++*+++++*++-. ... ..=**%*=+=+##%-                                                                                     
       =%##+===%*-. .:-:... .+++++*++++*+*- .. ::. ..-+*%+==*##%:                                                                                     
       :%##*==*#-...=++*=.. .:*++++++++++= . .-*+*- ..:+%#==###%.                                                                                     
        %%##+=%+. ..*+=-. ....=++++++++++.  ...-=++....:*%++%#%#                                                                                      
        -%###*#.  . ...... ...:+*+++++++-..... .. . .. .=%####%:                                                                                      
         #%##%+... .. -**.  ...=+*+++++*.. . .+#+. . ....#%#%##                                                                                       
          %##%:.. . .=@@%@:. ..:++++++++... .%@@@%  .....:#%%*                                                                                        
           *%* .... .+ =@@%... .*++++++-. . =-.%@@* ......%%-                                                                                         
           =%*. . ..-: :@@@:....+++++++... .@. #@@@.......*%-                                                                                         
           #%*+: ...*#-*%@@+....=+*+*+*.. .:@%+%%@@.. ..-+*%*                                                                                         
          -%%++*=.  *@@*=@@* .. -*+++++  . -@%@*-@@....++**%%.                                                                                        
          ##%+*+++..-@@@@@@=....::    . .. =@@@@@@@..:++++*%#:                                                                                        
          .+#+*+*++..@@@@@%=.              -+@@@@@=.-+*++**%+-                                                                                        
           *%+++++++.:@@@@--. . *######.   :=*@@@* =++++++*%*                                                                                         
           *%*++*+*++-.-=--... ###-:+#*%   .=---:.=*+**++++#+                                                                                         
        .:.=#*+++++++*+===..   %#######%.  ..+===+++++++++*#-....                                                                                     
      ..   :%#***+++*++*=....  *########   . .+*+*++++++*+%%.     .                                                                                   
            *%#+++=++++:... .   #%###%#     . .=+*++++===+#+                                                                                          
            :++**+++: . ..  .    :#@#:    :......-++*+++*%%...                                                                                        
         .:. :****: ... .. ..:    .-:     -......  .===+%%.    :                                                                                      
        .     -+*+::....  ...--.:::=-:.::-. .......::=+##:                                                                 .=+=:                      
             :.:*+-::.. ...  .---=- :==-=:.......::::-*#: ..                                                              :#*++#*+:                   
           ..   .+*-::::.....  ..     ....... ..::::=*#.    .                                                             #+:...-+#+.                 
          ..      -*+-::::......       .......::::-+*#%#     .                                                            #-::  . :**-                
          .        .+*+-::::.....       ...:::::-+*#%%%%#.                  .:-=+****+-:.                                .*-::. ....=*=               
                     .+*+-::::::::....:::-::::=**+-%%%#*#@-            .-+#%%##*+++++*##%#=.                             .#-:::. ....:#+              
                       .***+-:::::::::::::-=+***-::%%*+*+*%%*:.   .:=#%%#***++++=========+#%#:                            #-::::..... :#+             
                        +=-+***+==---==++****=-::::**++*+++*#%%%%%%#*++====+++**+=========++*##:                          #=::::.. ... .*=            
                        +=:::-=+*********+=-::::::.-+*++++*+++**+===========*++++++========++**#+                         =*:::::. .. ..-*-           
                        +=::::::::----::::::::::...:*+++*+++++*++++=========++++++++=======++*+*##:                       .#-::::.... . .=*.          
                        ==:::::::::::::::::::::.... ++++++*+++++*+++=========+++++*++======++*+++#%-                       #=:::::... .. .*+          
                        +-..:::::::::::::::::.... . ++++*++++++++++++========+++++++++=====+++++*+*%-                      =#:::::........-#.         
                        *:.. .::::::::::::::......  =*++*+++++++++++++========++++++++=====++++++++*#=                      #=::::: .... ..*+         
                        *.. .....:::::::...........-:++++++++++++++++++=======+++++++*+====++++++**+*#-                     ++:::::.. .  ..-*         
                       .*... ..........  ... ......=++++*++++++++++**+++======+++++*++*====++++++++++##:                    :#:-*##*+=-.. .:*-        
                       :+ ...................... ..=+++++++++++++++++++++=====++++++++++==++++++++++++##                     **%%%%#++++=..:+*        
                       -= ...................... ..++++++++++++++++++++++=====++++++++++==++++++++++++*#+                    =#%%%%#++++**=--#.       
                       =-..........................+++++++++++++++++++++*+====++++++++++=+++++++++++*++*#.                   -#%%%%#++++*++%=*.       
                       =-........................--+++++++++++++++++++++++====++++++++++++++++++++++++*+#*                   .#%%%%%+++*+++%%*:       
                       =-.. ............... .....+++++++++**+*++*++++++++++==++++++*++++*+**++++++++++++*#.                   #%%%%%*+*++++%%#-       
                       -=:......................:+*++++++*++*+*++++++++++++==++++++++***+**+++++++++++++*#+                   *#%%%%++++++*%%#-       
                       :++.. ...................+++*++++++++#*+*+++++++++++==*++++++++++#*+++++++++++++++#%.                  *=:---=++++*+%%#=       
                       .**- .. ................-+++*++++++++*%**+++++++++++=+++++++**+*#*++*+++++++++++++*#=                 .#-:::...-+++*%%#=       
                        ==+.................. .+++*++++++*++*%%**+++++++++++*+++++++*+#**+++++++++++++++++#*                 :*::::.....=+*%%#=       
                        .:*. .  ..............:*+++++++++++++#%#+++++++++++++++++++++*#+++++++++++++++++++##.                =*::::..... -#%%#-       
                         .*-.-. .. ...........+++++++++++++++#%%*+++++++++++++++++++*%*+++++++++++++++++++##:                *=:::..... . +%%*:       
                          +*.=:... .........:.*++++++++++++++*%%*+++++++++++++++++++##++++++++++++++++++++*#=               +#*=:......  .:+%#.       
                          .*-+:... .........::**+++++++++++++*%%#+++++++++++++++++++##*+++++++++++++++++++*#+              =####*-..... .:::%#        
                           +**=:....... ...:::#++++++++++++++*%%#++++++++**++++++*+-%#+++++++++++++++++++**#*             +####*+*+....  :::*+        
                           .#**:::...... .::::%*+++++++++++++*%%#+*+++++++++++*+=:.-%*++++++++++++++++++++*###:         :*##*#*+*++*: ...:::#:        
                            +#*+:::.. ...:::::#*+++++++++++++*%%*.:=+++++++++=:...:=%*+++++++++++++++++++++#####-.. ..-*#*:-**+++++++: .:::=#         
                             %#*+:-::..:::::::##+++++++++++++#%%*.. .......  ....::+%**+++++++++++++++++++*############+:::..+++*++++*.::::*=         
                             -%#*++-::::::::::#%**+++++++++++#%%+::............::::=%**+++++++++++++++++++*#########%%::.   ..++*+**+*#:::+*          
                              *##***=:::::::::-%*++++++++++++%%%=:::::......:::::::=%*++++++++++++++++++++*###########*  .. ...*++*++#%-:-#-          
                              .%%%#**=:-:::::::##++++++++++++%%%-::::::::::::::::::-%#++++++++++++++++++++*############:.... ..=+++*#%%*:*+           
                               =#%%#**+-+::::::+%*+++++++++**%%%-:::::::::::::::::::##*+++++++++++++++++++##%%%########=..... ..*+*%%%%%+*.           
                                %%%%%##***=:::::#*+++++++++**%%%::::::::::::::::::-=*%*+++++++++++++++++++##%%%%#######+.. .....*#%%%%%##.            
                                :%#%%%%##***+-::+#++++++++++#%%*:::::::::::::::-=***#%#+++*++++++++++++++*##%%%%%%%####* ......:*%%%#%#*:             
                                 %**%%#%%%###****%*++++++*+*%%%-::::::::::::-+***##%%%%*+++++++++++++++++*##%%%%%%%%%%#*....::::+%%%%##.              
                                 -#++#%%%%%%%%-=+%+++++++++#%%%:::::--=++******#%%%%%%%%++++++++++++++++*##%%%%%%%%%%%%+::::::::+%%##+                
                                  %*++*%%%%%#%.  #*++++++++#%%%**********#%%%%%%%%%%%%%##+++++++++++++++*###*%%%%%%%%%%-::::::::*##*:                 
                                  +#+*++#%%%%@   **+++*+++*%%%=-::::..  .#%%%%%%%%%%%%%%%#+*+++++++++++*##%* -####%%%%+:::::::-+#*=.                  
                                  :%+++++%%%%@   +#+++++++%%%%            #%%%%%%%%%%%%%%%#*+++****+++*###%-   -+#####=+==++*##*-                     
                                   #*+**+#%%%#   =#*++++*#%%%#             +%@%%%%%%%%%@@%%%#+++++++**###%%.     .-+**#####*+-.                       
                                   *#+*++#%%%=   =%*++++*%%%%-               +%@%%%%%@@@@+=#%%#*****####%%+                                           
                                   =%#+++#%%%:   =%%+++*%#%%#                 .@@@@@@@@@@  .@#########%%%%.                                           
                                   -%%**#%%%%    =%#%%%%%%%%+             .#%%@%@@@@@@%@:    :*%%%%%#%%%%+                                            
                                -#%%%%%%%%%%%    *%%%%%%%%%%.            :@%%%%%%%@@@@@.      *%%%%%%%%%%                                             
                               *%#######%%%%#    #%%%%%%%#%=             %%%%%%@%%%%%%@   .=++#%%%%%%%%#.                                             
                              =###########%%=  :+%####%%%%%              @%%%%@%%%%%%%@ .*%######%%%%%#.                                              
                              %######%##*#%%  =%########%%-              :%%%%%%%%%%@%-.###########%%%-                                               
                              %%%###%####%%* =###########%:                *#*@@%@@@+ .%##%%#######%%%:                                               
                              .:@@%@%##%%@+ .%##%########@.                    .:.     %##@#*%%#####%*                                                
                                .::.-%%#=.  :##%########%+                             %%@%#%@#####%#.                                                
                                             *#%##%####%+                               ::%%@%###%%+                                                  
                                               #%#*%%%*:                                  .-:+#%#+:                                                   
                                                .  ==:                                        .                                                       
                                                                                                                                                      

`


const asciiART2 = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣾⣿⣷⣶⣦⣄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣾⡇⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀
⢀⣀⣀⣀⣠⣴⣾⣿⣿⠃⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆
⠈⠻⢿⣿⣿⣿⡿⣟⠃⠀⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡧
⠀⠀⠀⠀⠈⠈⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣼⣿⣿⣿⣿⣿⣿⣿⠇
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢛⡻⠋⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠙⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢛⢛⢛⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
`

function extractHardcodedStrings(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');

  const regex = /(['"`])(?:\\[\s\S]|(?!\1).)*?\1/g;
  const matches = [];

  let match;
  while ((match = regex.exec(code)) !== null) {
    const quote = match[1];
    const literal = match[0].slice(1, -1);
    const index = match.index;

    const before = code.slice(0, index);
    const lineNumber = before.split('\n').length;

    matches.push({
      value: literal,
      line: lineNumber
    });
  }

  return matches;
}

function listAllFilesAndFolders(startPath) {

  let files = [];
  let folders = [];

  function traverse(currentPath) {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true })
    for (const entrie of entries) {
      const fullPath = path.join(currentPath, entrie.name)
      if (entrie.isDirectory()) {
        folders.push(fullPath)
        traverse(fullPath)
      } else {
        files.push(fullPath)
      }
    }
    return { files, folders }
  }

  return traverse(startPath)
}

function isHighEntropy(str, threshold = 3.5) {
  function calculateEntropy(str) {
    if (!str) return 0;

    const freqMap = {};
    for (let char of str) {
      freqMap[char] = (freqMap[char] || 0) + 1;
    }

    const n = str.length;
    let entropy = 0;
    for (let char in freqMap) {
      const p = freqMap[char] / n;
      entropy += p * Math.log2(p);
    }

    return -entropy;
  }
  const entropy = calculateEntropy(str);
  return { entropy, threshold, state: entropy >= threshold };
}

function writeAnalytics(content, fileType, folderName = name.split(" ").join("_")) {

  function generateFileName(n) {
    const fileName = n.toString().padStart(15, '0')
    return fileName
  }

  const currentDir = process.cwd()
  const targetDir = path.join(currentDir, folderName);


  if (!fs.existsSync(targetDir) && !fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir)
    // this target dir is going to be in 2nd docker volume mount becaus ethis is the point where my docker is going to write 
  }
  const filesNfolders = listAllFilesAndFolders(targetDir);
  const fileName = generateFileName(filesNfolders.files.length + 1) + fileType
  const filePath = path.join(targetDir, fileName);
  fs.appendFileSync(filePath, content + '\n', 'utf-8')
}

function getTimeStamp() {
  const now = new Date();
  const custom =
    now.getFullYear() + '-' +
    String(now.getMonth() + 1).padStart(2, '0') + '-' +
    String(now.getDate()).padStart(2, '0') + ' ' +
    String(now.getHours()).padStart(2, '0') + ':' +
    String(now.getMinutes()).padStart(2, '0') + ':' +
    String(now.getSeconds()).padStart(2, '0');

  return custom

}

function matchesRegex(str, regexPattern) {
  const regex = new RegExp(regexPattern);
  return regex.test(str);
}

export function styledLogs(text, border = false, ...styles) {
  const ConsoleStyles = {
    reset: '\x1b[0m',

    bold: '\x1b[1m',
    dim: '\x1b[2m',
    italic: '\x1b[3m',
    underline: '\x1b[4m',
    inverse: '\x1b[7m',
    hidden: '\x1b[8m',
    strikethrough: '\x1b[9m',

    black: '\x1b[30m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',

    brightBlack: '\x1b[90m',
    brightRed: '\x1b[91m',
    brightGreen: '\x1b[92m',
    brightYellow: '\x1b[93m',
    brightBlue: '\x1b[94m',
    brightMagenta: '\x1b[95m',
    brightCyan: '\x1b[96m',
    brightWhite: '\x1b[97m',

    bgRed: '\x1b[41m',
    bgGreen: '\x1b[42m',
    bgYellow: '\x1b[43m',
    bgBlue: '\x1b[44m',
    bgMagenta: '\x1b[45m',
    bgCyan: '\x1b[46m',
    bgWhite: '\x1b[47m',

    bgBrightRed: '\x1b[101m',
    bgBrightGreen: '\x1b[102m',
    bgBrightYellow: '\x1b[103m',
    bgBrightBlue: '\x1b[104m',
    bgBrightMagenta: '\x1b[105m',
    bgBrightCyan: '\x1b[106m',
    bgBrightWhite: '\x1b[107m',
  };

  const start = styles.map((s) => ConsoleStyles[s] || '').join('');
  const reset = ConsoleStyles.reset;

  const content = `${start}${text}${reset}`;
  const length = text.length + 4;

  const top = '┌' + '─'.repeat(length) + '┐';
  const middle = `│  ${content}  │`;
  const bottom = '└' + '─'.repeat(length) + '┘';

  if (border) {

    console.log(ConsoleStyles.yellow, top);
    console.log(ConsoleStyles.red, middle);
    console.log(ConsoleStyles.yellow, bottom, ConsoleStyles.reset);
  } else {
    console.log(`${content}`);
  }
}


(function mainProgram() {
  try {
    if (!name || !tagline) {
      throw new Error('Name or tagline variables are undefined');
    }
    styledLogs(`⣿⣿ ${name} | ${tagline} `, true, 'blue');

    const args = process.argv.slice(2);
    const dirArgs = args.find((arg) => arg.startsWith("--dir_path="));
    const entropyThreshold = args.find((arg) => arg.startsWith("--entropy="));

    if (!dirArgs) {
      throw new Error('Directory path is required. Usage: --dir_path=<path>');
    }

    const dir_path = dirArgs.split("=")[1];
    if (!dir_path || typeof dir_path !== 'string' || dir_path.trim() === '') {
      throw new Error('Invalid directory path provided');
    }

    let entropy_threshold;
    try {
      entropy_threshold = entropyThreshold ? parseFloat(entropyThreshold.split("=")[1]) : 3.5;
      if (isNaN(entropy_threshold) || entropy_threshold < 0) {
        throw new Error('Invalid entropy threshold value');
      }
    } catch (error) {
      styledLogs(`⣿⣿ Error parsing entropy threshold: ${error.message}. Using default value 3.5`, true, 'yellow');
      entropy_threshold = 3.5;
    }

    const { files, folders } = listAllFilesAndFolders(dir_path);

    if (!files || !Array.isArray(files)) {
      throw new Error('Failed to list files from directory');
    }

    const filesLength = files.length;
    if (filesLength === 0) {
      styledLogs(`⣿⣿ ${name} | No files found in directory: ${dir_path}`, true, 'red');
    }

    // Aggregated results
    const allEntropyData = [];
    const allRegexPatternData = [];

    for (let i = 0; i < filesLength; i++) {
      try {
        const filePath = files[i];

        if (!filePath || typeof filePath !== 'string') {
          throw new Error(`Invalid file path at index ${i}`);
        }

        let content;
        try {
          content = extractHardcodedStrings(filePath);
        } catch (error) {
          styledLogs(`⣿⣿ ${name} | Error reading file ${filePath}: ${error.message}`, true, 'red');
          continue;
        }

        if (!Array.isArray(content)) {
          styledLogs(`⣿⣿ ${name} | No valid content extracted from ${filePath}`, true, 'red');
          continue;
        }

        if (content.length > 0) {
          const entropyData = [];
          const regexPatternData = [];

          for (let j = 0; j < content.length; j++) {

            try {
              // if (!content[j]?.value || !content[j]?.line) {
              //   throw new Error(`Invalid content format at index ${j}`);
              // }

              const entropyStatus = isHighEntropy(content[j].value, entropy_threshold);
              if (entropyStatus?.state) {
                entropyData.push({
                  filePath: filePath,
                  entropy_string: content[j].value,
                  line_number: content[j].line,
                  ...entropyStatus
                });
              }
            } catch (error) {
              styledLogs(`⣿⣿ ${name} | Error processing entropy for string at ${filePath} | line_number : ${content[j]?.line} | content : ${content[j].value} | error_message : ${error.message}`, false, 'red');
            }
          }

          try {
            if (!patternFileContent || typeof patternFileContent !== 'object') {
              throw new Error('Pattern file content is invalid or undefined');
            }
            for (let j = 0; j < content.length; j++) {
              for (const patterKey in patternFileContent) {
                try {
                  if (matchesRegex(content[j].value, patternFileContent[patterKey])) {
                    regexPatternData.push({
                      filePath,
                      type: patterKey,
                      matchedValue: content[j].value,
                      line_number: content[j].line
                    });
                  }
                } catch (error) {
                  styledLogs(`⣿⣿ ${name} | Error matching regex for ${patterKey} in ${filePath}: ${error.message}`, false, 'red');
                }
              }
            }
          } catch (error) {
            styledLogs(`⣿⣿ ${name} | Error processing regex patterns: ${error.message}`, false, 'red');
          }

          allEntropyData.push(...entropyData);
          allRegexPatternData.push(...regexPatternData);
        }
      } catch (error) {
        styledLogs(`⣿⣿ ${name} | Error processing file ${files[i]}: ${error.message}`, true, 'red');
        continue;
      }
    }

    try {
      if (allEntropyData.length === 0 && allRegexPatternData.length === 0) {
        writeAnalytics(`${metaData} No Secrets are present at the time of scan :: ${getTimeStamp()} \n\n\n ${asciiART}`, '.log');
      } else {
        const result = { ENTROPY: allEntropyData, SECRETS: allRegexPatternData };
        writeAnalytics(`${metaData} Scanned result :: ${getTimeStamp()} \n ${JSON.stringify(result, null, 2)} \n\n\n ${asciiART}`, '.log');
      }
      if (filesLength !== 0) {
        styledLogs(`⣿⣿ ${name} | scanned secrets are written inside ${nameVar}`, true, 'green');
      }
    } catch (error) {
      styledLogs(`${name} | Error writing analytics: ${error.message}`, false, 'red');
    }

  } catch (error) {
    styledLogs(`⣿⣿ ${name} | Fatal error: ${error.message}`, true, 'red');
    process.exit(1);
  }
})();
