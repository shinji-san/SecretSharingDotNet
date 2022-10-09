// ----------------------------------------------------------------------------
// <copyright file="SharesEnumerator.cs" company="Private">
// Copyright (c) 2019 All Rights Reserved
// </copyright>
// <author>Sebastian Walther</author>
// <date>04/20/2019 10:52:28 PM</date>
// ----------------------------------------------------------------------------

#region License
// ----------------------------------------------------------------------------
// Copyright 2019 Sebastian Walther
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
#endregion

namespace SecretSharingDotNet.Cryptography
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;

    /// <summary>
    /// Supports a iteration over <see cref="Shares{TNumber}"/> collection.
    /// </summary>
    /// <typeparam name="TNumber">The type of integer which is used by the <see cref="FinitePoint{TNumber}"/> items of the
    /// <see cref="Shares{TNumber}"/> collection.</typeparam>
    public sealed class SharesEnumerator<TNumber> : IEnumerator<FinitePoint<TNumber>>
    {
        /// <summary>
        /// Saves a list of <see cref="FinitePoint{TNumber}"/>.
        /// </summary>
        private readonly ReadOnlyCollection<FinitePoint<TNumber>> shareList;

        /// <summary>
        /// Saves the current of the enumerator
        /// </summary>
        private int position = -1;

        /// <summary>
        /// Initializes a new instance of the <see cref="SharesEnumerator{TNumber}"/> class.
        /// </summary>
        /// <param name="shares">A collection of <see cref="FinitePoint{TNumber}"/> items representing the shares.</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="shares"/> is <see langword="null"/></exception>
        public SharesEnumerator(Collection<FinitePoint<TNumber>> shares)
        {
            _ = shares ?? throw new ArgumentNullException(nameof(shares));
            this.shareList = new ReadOnlyCollection<FinitePoint<TNumber>>(shares);
        }

        /// <summary>
        /// Advances the enumerator to the next element of the <see cref="Shares{TNumber}"/> collection.
        /// </summary>
        /// <returns><see langword="true"/> if the enumerator was successfully advanced to the next element;
        /// <see langword="false"/> if the enumerator has passed the end of the <see cref="Shares{TNumber}"/> collection.</returns>
        public bool MoveNext()
        {
            this.position++;
            return this.position < this.shareList.Count;
        }

        /// <summary>
        /// Sets the enumerator to its initial position, which is before the first element in the <see cref="Shares{TNumber}"/> collection.
        /// </summary>
        public void Reset() => this.position = -1;

        /// <summary>
        /// Performs tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose() { }

        /// <summary>
        /// Gets the element in the <see cref="Shares{TNumber}"/> collection at the current position of the enumerator.
        /// </summary>
        object IEnumerator.Current => this.Current;

        /// <summary>
        /// Gets the element in the <see cref="Shares{TNumber}"/> collection at the current position of the enumerator.
        /// </summary>
        public FinitePoint<TNumber> Current
        {
            get
            {
                try
                {
                    return this.shareList[this.position];
                }
                catch (IndexOutOfRangeException)
                {
                    throw new InvalidOperationException();
                }
            }
        }
    }
}
