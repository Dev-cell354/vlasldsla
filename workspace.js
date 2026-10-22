
async function loadWorkspace(){
 const projects=await fetch('/api/projects').then(r=>r.json());
 const pinned=await fetch('/api/pinned').then(r=>r.json());
 const library=await fetch('/api/library').then(r=>r.json());

 console.log({projects,pinned,library});
}

loadWorkspace();
