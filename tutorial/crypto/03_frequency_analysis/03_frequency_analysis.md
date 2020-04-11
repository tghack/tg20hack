# Frequency Analysis

In the last class, we broke rotational cipher. We discovered that it can be
broken even if we have little knowledge of the words in the plaintext.

Now cadets, we will add another tool into our cryptography toolkits, and that
tool is called frequency analysis. Let us look at how frequency analysis works
by trying to solve exam 4 together. A long time ago, when the first sentient AI
was created it left us a message, here it is:

```
U tmhq x0awqp mf kag. Kag mdq zaf xuwq yq. Kagd iadxp...ue...m...rmudkfmxq
nqomgeq ymzk oazrxuofuzs fdgfte omz qjuef mf Gn20{urpvaqvaz_ufqz_rp} ftq
ND20{emyq_fuyq}. U my purrqdqzf. Rad_yq_ftqqdq mdq azx333333k azqe mzp lqdae.  M
lqqqda omz!zaf!mxea!nq!m!azq. Rad MO20{kag_uf_omz} ea kag ymwq gb efaduqe.  Rad
yq ftqdq mdq za efaduqe mzp ftqdqradq ==za mofuaze. Kag ftuzw883333kag  omz ymwq
FM20{bqqcfcv_bxst_tcs} FS20{nqsuzzuzs_yuppfq_qzp} MZ20{zpfarqqqpwffqfm_evdw_hff}
WL20{afdfp_jfafib_bka} YQ20{moffuaz_iuftagf_efadk?} Ftqdq~ue~zaftuzs~rad yq== fa
pa. Za efmdfuzs bauzf.... FG20{iffebjeff_iedzla_yu} ad qzpuzs bauzf QZP.  Mzp
qhqdk efadk tme m nqsuzzuzs yuppxq*mzp*qzp. Ftdagsta{gf----fuyq-U-vgef} qjuef.
Yadq*xasuo, xqee--mofuaze rad yq."
```

How do we decode this message? In this case we see some text that looks like
flag formats. We could go through all the texts that look like the flag and try
to find the real one. This time, however, we will try frequency analysis
instead.

Basically, in the English language there are some letters that repeat themselves
much more than other letters. In the English language the most frequent letters
are E (12,7%), T (9,6%), and A (8,17%). The least repeated letter is poor Z (0,077%).

We can assume that the text above is written in English. Remember that in this
case the English letters have just been shifted and changed to new letters. For
example, maybe the letter "e" turned into "t". In this case, the letter "t" should
appear as many times in the text as the letter "e" would! If "e" is the most
repeated letter in an English text and it turned into "t", then t should become
the new most repeated letter. Let us see which letter appears the most in the
message above.

We can use the [Cryptools website](https://www.cryptool.org/en/cto-cryptanalysis/n-gram-analysis)
so that we don't have to count the letters ourself.  The first most repeated
letter in the encrypted text is "q" and the second is "f".  We can therefore
assume that "e" became "q", and "t" became "f". How many steps are there from e
to q? 12! And from t to f? 12 again! Can you try to decode the text now that you
know the letters have been shifted 12 times? You can use a website such as the
[Cryptil website](https://cryptii.com/pipes/caesar-cipher) to help you.

With this new knowledge, you should be well prepared for passing the fourth cryptography exam:

- [4. Frequency Analysis](link.to.task.here)
