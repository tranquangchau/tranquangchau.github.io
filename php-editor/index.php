<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <meta http-equiv="content-language" content="en"      />
    <meta http-equiv="content-script-type" content="text/javascript" />
    <meta http-equiv="imagetoolbar" content="no"/>    
   
    <title>PHP write and run php code online</title>
    <link rel="stylesheet" href="./style.css">
  </head>
  <body>
    <main id="main"></main>
    <a class="skip-link" href="#">Skip to main</a>
  <section class="hero is-info">
  <header class="nav">
    <div class="container">
      <div class="nav-left">
        <a class="nav-item logo" href="#">
          <span class="name"><i class="fa fa-pencil-square-o name-icon" aria-hidden="true"></i>PHPOnline<span class="slogan"> - write and run your php</span></span>
        </a>
        <a href="#" class="enable_menu icon"><i class="fa fa-bars" aria-hidden="true"></i></a>
      </div>
    </div>
  </header>
</section>  <section class="editor-tool-section">
     <section class="editor-tool is-one-quarter is-pulled-left">
      <div class="nlp-try-form">
        <div class="editor-panel">
          <div class="editor">
              <label class="tag_open" for="editor_code">&lt;?php</label>
              <form id="code_frm" name="code_form" method="POST" action="">
                <div id="editor_code" name="editor_code" class="editor_code">echo 'Hello World!';</div>

 <?php if(!empty($_POST['editor_code_editor'])){
		  $code_to_parse = $_POST['editor_code_editor'];
		  ?>
		  <textarea name="editor_code_editor" class="editor_code_editor hide_e" id="editor_code_editor"><?php echo $code_to_parse; ?></textarea>
		  <?php
		}else{?>
			<textarea name="editor_code_editor" class="editor_code_editor hide_e" id="editor_code_editor">echo 'Hello World!';</textarea>
		<?php } ?>

                <div class="text-align-right">
                  <input type="submit" name="run_code" id="run_code" class="button is-info run_code" value="Run Code" translate="no"/>
                </div>
              </form>
            </div>
        </div>
      </div>
      <div class="result">
	  <?php if(!empty($_POST['editor_code_editor'])){
		  $code_to_parse = $_POST['editor_code_editor'];
		  
		  ob_start();
		  $str = "<?php $code_to_parse 123; ?>";
		  eval("?> $str <?php ");
		  
$this_string = ob_get_contents();
ob_end_clean();
		  
		  echo $this_string;

	  }
	  ?>
	  </div>
      
    </section>
  
  </section>
  <script src="./script.js" type="text/javascript" charset="utf-8"></script>
    <footer class="footer">
  <div class="footer-nav">
    PHP Version: <?php echo phpversion();?>
  </div>
  <div class="small-bottom">
    write your PHP code using our online code editor/compiler.
  </div>
 
  </body>
</html>
