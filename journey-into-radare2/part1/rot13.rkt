#lang racket

(define (rot13 s)
  (list->string
    (for/list ([ch (string->list s)])
      (define ord (char->integer ch))
      (define base (if (< ord 96) 65 97))
      (define rotated (+ (modulo (+ 13 (- ord base)) 26) base))
      (integer->char rotated))))
