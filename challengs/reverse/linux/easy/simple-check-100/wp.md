# simple-check-100



```
  if ( check_key((int)v42) )
  	interesting_function((int)&v13);
  else
    puts("Wrong");
```

just patch logic jz as jnz

```
  if ( check_key((int)v42) )
    puts("Wrong");
  else
    interesting_function((int)&v13);
```

run this program we will get flag