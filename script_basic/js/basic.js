var g_expires=1000*60*60*24*365*7; 
var ischrome=false;
var isgecko=false;
var isopera=false;
var ismsie=false;
var issafari=false;

if (navigator.appName=="Netscape"){
	if (navigator.userAgent.indexOf("Chrome")>=0) ischrome=true;
	if (navigator.userAgent.indexOf("Gecko")>=0) isgecko=true;
	if (navigator.userAgent.indexOf("Safari")>=0) issafari=true;
} else {
	if (navigator.userAgent.indexOf("Opera")>=0) isopera=true;
	if (navigator.userAgent.indexOf("MSIE")>=0) ismsie=true;
}

function setCookie(name, value) { 
  var expires=g_expires;
  path="/";
  domain=".iblogbox.com";
  secure=false;
  var today = new Date(); 
  today.setTime( today.getTime() ); 
  var expires_date = new Date( today.getTime() + (expires) ); 
  document.cookie = name + "=" +escape( value ) + 
          ( ( expires ) ? ";expires=" + expires_date.toGMTString() : "" ) + //expires.toGMTString() 
          ( ( path ) ? ";path=" + path : "" ) + 
          ( ( domain ) ? ";domain=" + domain : "" ) + 
          ( ( secure ) ? ";secure" : "" ); 
} 

function getCookie( name ) {
  var nameOfCookie = name + "=";
  var x = 0;
  while ( x <= document.cookie.length ) {
    var y = (x+nameOfCookie.length);
    if ( document.cookie.substring( x, y ) == nameOfCookie ) {
      if ( (endOfCookie=document.cookie.indexOf( ";", y )) == -1 )
         endOfCookie = document.cookie.length;
      return unescape( document.cookie.substring( y, endOfCookie ) );
    }
    x = document.cookie.indexOf( " ", x ) + 1;
    if ( x == 0 ) break;
  }
  return "";
}	
	
function setstorage(name,value){
	if (window.localStorage){
		localStorage[name]=value+'';
	}else{
		setCookie(name, value); 
	}
}

function getstorage(name){
	var s;
	if (window.localStorage){
		s=localStorage[name];
	}else{
		s=getCookie(name);
	}
	return s;
}

function _getid(id){
	return document.getElementById(id);
}	

function _getinnertext(f){
	var s=f.innerText;
	if (!s){
		s=f.innerHTML;
		s=s.replace(/(<br>)/ig,' '); 
		s=s.replace(/(<[^>]+>)/g,''); 
	}
	return s;
}

function _fnselect(objId){
   if (document.selection)
		document.selection.empty();
   else if (window.getSelection)
		window.getSelection().removeAllRanges();

   if (document.selection) {
      var range = document.body.createTextRange();
      range.moveToElementText(document.getElementById(objId));
      range.select();
   } else if (window.getSelection) {
      var range = document.createRange();
      range.selectNode(document.getElementById(objId));
      window.getSelection().addRange(range);
   }
}

function getOffset(b,e) {
    var a = 0;
    var c = 0;

    while (b && !isNaN(b.offsetLeft) && !isNaN(b.offsetTop)) {
        a += b.offsetLeft;
        c += b.offsetTop;
        b = b.offsetParent;
    }

    if (e) {
    	b2=e.target;
    	while (b2 && !isNaN(b2.scrollLeft) && !isNaN(b2.scrollTop)) {
    		if (b2==document.body) break;
      	  	a = a-b2.scrollLeft;
      	  	c = c-b2.scrollTop;
			if (b2.parentElement) b2=b2.parentElement;
			else b2=b2.parentNode;
    	}
    }
       
    return {
        left: a,
        top: c
    }
}

function r13(s) {
function rot( t, u, v ) {
 return String.fromCharCode( ( ( t - u + v ) % ( v * 2 ) ) + u );
}
 var b = [], c, i = s.length,
  a = 'a'.charCodeAt(), z = a + 26,
  A = 'A'.charCodeAt(), Z = A + 26;
 while(i--) {
  c = s.charCodeAt( i );
  if( c>=a && c<z ) { b[i] = rot( c, a, 13 ); }
  else if( c>=A && c<Z ) { b[i] = rot( c, A, 13 ); }
  else { b[i] = s.charAt( i ); }
 }
 return b.join( '' );
}

function proc_exload(){
	var a=document.getElementsByTagName('*');
	for(var i = 0; i < a.length; i++){    
		if (a[i].tagName=='TEXTAREA'){
			a[i].spellcheck=false;
		}else if (a[i].tagName=='INPUT' && a[i].type && a[i].type.toLowerCase()=='text'){
			a[i].spellcheck=false;
		}
	}
}
if (window.addEventListener) window.addEventListener("load", proc_exload, false);

function proc_exload_save(){
	if (isopera || issafari){
		setInterval(function(){
			if (window.savestorage){
				savestorage();
			}
		},2000);
	}
}

if (window.addEventListener){
	window.addEventListener("load", proc_exload_save, false);
}else if (window.attachEvent){
	window.attachEvent("onload", proc_exload_save);
}