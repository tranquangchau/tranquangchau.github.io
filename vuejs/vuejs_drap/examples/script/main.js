var id=4;

var vm = new Vue({
	el: "#main",
	data: {
		list: [ {name: "John", id:0}, 
				{name: "Joao", id:1}, 
				{name: "Jean 2", id:2},
				{name: "Jean 3", id:3},
				{name: "Jean 4", id:4},
			],
		dragging: false
	},
	methods:{
			add: function(){
				this.list.push({name:'Juan '+id, id: id++});
			},
			replace: function(){
				this.list=[{name:'Edgard', id: id++}]
			},
			test:function(){
				alert('after change');
				console.log('after change');
			}
		}
	});
