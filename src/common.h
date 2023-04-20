/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Common header
 * Copyright (c) 2006-2023 Roy Marples <roy@marples.name>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef COMMON_H
#define COMMON_H

#if __GNUC__ > 2 || defined(__INTEL_COMPILER)
# ifndef __packed
#  define __packed __attribute__((__packed__))
# endif
# ifndef __unused
#  define __unused __attribute__((__unused__))
# endif
#else
# ifndef __packed
#  define __packed
# endif
# ifndef __unused
#  define __unused
# endif
#endif

/* Needed for rbtree(3) compat */
#ifndef __RCSID
#define __RCSID(a)
#endif
#ifndef __predict_false
# if __GNUC__ > 2
#  define	__predict_true(exp)	__builtin_expect((exp) != 0, 1)
#  define	__predict_false(exp)	__builtin_expect((exp) != 0, 0)
#else
#  define	__predict_true(exp)	(exp)
#  define	__predict_false(exp)	(exp)
# endif
#endif
#ifndef __BEGIN_DECLS
# if defined(__cplusplus)
#  define	__BEGIN_DECLS		extern "C" {
#  define	__END_DECLS		};
# else /* __BEGIN_DECLS */
#  define	__BEGIN_DECLS
#  define	__END_DECLS
# endif /* __BEGIN_DECLS */
#endif /* __BEGIN_DECLS */

#endif
