var { ContainerMixin, ElementMixin } = window.VueSlicksort;

var SortableList = {
  mixins: [ContainerMixin],
  template: `
    <ul class="list">
      <slot />
    </ul>
  `,
};

var SortableItem = {
  mixins: [ElementMixin],
  props: ['item'],
  template: `
    <li class="list-item" @sortend="changehanve">{{item}}</li>
  `,
  methods:{
	  changehanve:function(event){
		alert('132')
		alert(event)
			//console.log(this.items);
		  //alert('test')
	  },
  }
};

var app = new Vue({
	el: '#app',
  name: 'Example',
  components: {
    SortableItem,
    SortableList,
  },
  data: function() {
    return {
	//items: ['Item 1', 'Item 2', 'Item 3', 'Item 4', 'Item 5', 'Item 6', 'Item 7', 'Item 8'],      
	  items: [
		{'name':'Item 1', 'index':1}, 
		{'name':'Item 2', 'index':2}, 
		{'name':'Item 3', 'index':3}, 
		{'name':'Item 4', 'index':4}
	  ],	 
    };
  },
  methods:{
	  get_data:function(){
			console.log(this.items);
		  //alert('test')
	  },
	  changehanve:function(event){
	  alert('132')
		alert(event)
			//console.log(this.items);
		  //alert('test')
	  },
  }
});
