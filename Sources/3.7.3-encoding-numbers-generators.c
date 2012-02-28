 int YourNumber = 0x000001EB;
 for (short i=0x3030;i<0x7A7A;i++){
	 for (short l=0x3030;l<0x7A7A;l++){
		 char* n = (char*)&i;
		 char* m = (char*)&l;
		 if (((i * l)& 0xFFFF)==YourNumber){
				//cout << (int*)i << "       " << (int*)l<< "\n";
			 for(int s=0;s<2;s++){
				   if (!(((n[s] > 0x30 && n[s] < 0x39) || \
						  (n[s] > 0x41 && n[s] < 0x5A) || \
						  (n[s] > 0x61 && n[s] < 0x7A)) && \
						 ((m[s] > 0x30 && m[s] < 0x39) || \
						  (m[s] > 0x41 && m[s] < 0x5A) || \
						  (m[s] > 0x61 && m[s] < 0x7A)))) 
						goto Not_Yet;
			 }
			 cout << (int*)i << "       " << (int*)l << "        " << (int*)((l*i) & 0xFFFF)<< "\n";
		 }
		 
Not_Yet:
	continue;              
	 }  
 };