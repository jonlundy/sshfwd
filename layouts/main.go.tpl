{{define "main"}}
<!DOCTYPE html>

<html>
<head>
    <meta charset="UTF-8">
	{{template "meta" .}}
    <title>SSH Fwd</title>

    <link href="/assets/bootstrap.min.css" rel="stylesheet" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">
    <link href="/assets/sshfwd.css" rel="stylesheet" crossorigin="anonymous">
</head>

<body>

<div class="container-fluid">
      <div class="header clearfix">
        <nav>
          <ul class="nav nav-pills pull-right">
            <li role="presentation"><a href="/">Home</a></li>
          </ul>
        </nav>
        <h3 class="text-muted">SSH Fwd</h3>
      </div>
</div>

<div class=container>
	{{template "content" .}}
</div>

</body>
</html>
{{end}}
