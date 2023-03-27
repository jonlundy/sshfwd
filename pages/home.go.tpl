{{template "main" .}}

{{define "meta"}}
    <meta http-equiv="refresh" content="30">
{{end}}

{{define "content"}}
  <h2>What is this?</h2>

  <p>This is a reverse proxy service that uses SSH as the transport. It works similar to ngrok or localtunnel.me.</p>

  <p>
    You run the service on a internet addressible host and ssh to it. Using ssh remote forwards (ie. ssh -R) the port 
    on the remote host will be forwared to the configured port on your local machine.
  </p>

  <h2>How does it work?</h2>

  <p>
    <ol>
      <li>You add your SSH public key</li>
      <li>Connect to SSH</li>
      <li>???</li>
      <li>Profit!</li>
    </ol>
  </p>

  <form class="form-inline" method="POST" action="/peers/req">
    <label>SSH Public Key:</label>
    <div class="input-group input-group-sm">
        <input class="form-control" type="text" name="pub" placeholder="ssh-key ...">
    </div>
    <button class="btn btn-default" type="submit">Submit</button>
  </form>

  <div class=row>
    <h2>Connections</h2>
    {{ with $args := . }}
    {{ range $user := .Users }}
     <div class="panel panel-primary">
        <div class="panel-heading">
          <a href="/user/{{ $user.Name }}">
            {{ $user.Name }}
          </a>

          <div style='float:right'>
          {{ if $user.Active }}
            <a href="/user/{{ $user.Name }}" class='btn btn-success'>Active</a>
          {{ else }}
            <a href="/user/{{ $user.Name }}" class='btn btn-danger'>Disconnected</a>
          {{ end }}  
          </div>
        </div>
        <div class="panel-body"> 
          <pre>ssh -T -p {{ $args.ListenPort }} {{ $user.Name }}@{{ $args.DomainName }} -R "{{ $user.BindPort }}:localhost:$LOCAL_PORT" -i $PRIV_KEY</pre>
        </div>
      </div>
    {{ end }}
  </div>
  {{ end }}
  {{ end }}
