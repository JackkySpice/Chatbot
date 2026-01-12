.class public Landroidx/appcompat/view/menu/n40$c;
.super Landroidx/appcompat/view/menu/n40;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/n40;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "c"
.end annotation


# instance fields
.field public final transient o:Landroidx/appcompat/view/menu/n40;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/n40;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/n40;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    return-void
.end method


# virtual methods
.method public A(II)Landroidx/appcompat/view/menu/n40;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/n40$c;->size()I

    move-result v0

    invoke-static {p1, p2, v0}, Landroidx/appcompat/view/menu/jj0;->m(III)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {p0, p2}, Landroidx/appcompat/view/menu/n40$c;->D(I)I

    move-result p2

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/n40$c;->D(I)I

    move-result p1

    invoke-virtual {v0, p2, p1}, Landroidx/appcompat/view/menu/n40;->A(II)Landroidx/appcompat/view/menu/n40;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/n40;->y()Landroidx/appcompat/view/menu/n40;

    move-result-object p1

    return-object p1
.end method

.method public final C(I)I
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/n40$c;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    sub-int/2addr v0, p1

    return v0
.end method

.method public final D(I)I
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/n40$c;->size()I

    move-result v0

    sub-int/2addr v0, p1

    return v0
.end method

.method public contains(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/n40;->contains(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public get(I)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/n40$c;->size()I

    move-result v0

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/jj0;->g(II)I

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/n40$c;->C(I)I

    move-result p1

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public i()Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/m40;->i()Z

    move-result v0

    return v0
.end method

.method public indexOf(Ljava/lang/Object;)I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/n40;->lastIndexOf(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/n40$c;->C(I)I

    move-result p1

    goto :goto_0

    :cond_0
    const/4 p1, -0x1

    :goto_0
    return p1
.end method

.method public bridge synthetic iterator()Ljava/util/Iterator;
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/n40;->r()Landroidx/appcompat/view/menu/p31;

    move-result-object v0

    return-object v0
.end method

.method public lastIndexOf(Ljava/lang/Object;)I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/n40;->indexOf(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/n40$c;->C(I)I

    move-result p1

    goto :goto_0

    :cond_0
    const/4 p1, -0x1

    :goto_0
    return p1
.end method

.method public bridge synthetic listIterator()Ljava/util/ListIterator;
    .locals 1

    .line 1
    invoke-super {p0}, Landroidx/appcompat/view/menu/n40;->s()Landroidx/appcompat/view/menu/q31;

    move-result-object v0

    return-object v0
.end method

.method public bridge synthetic listIterator(I)Ljava/util/ListIterator;
    .locals 0

    .line 2
    invoke-super {p0, p1}, Landroidx/appcompat/view/menu/n40;->t(I)Landroidx/appcompat/view/menu/q31;

    move-result-object p1

    return-object p1
.end method

.method public size()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    invoke-virtual {v0}, Ljava/util/AbstractCollection;->size()I

    move-result v0

    return v0
.end method

.method public bridge synthetic subList(II)Ljava/util/List;
    .locals 0

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/n40$c;->A(II)Landroidx/appcompat/view/menu/n40;

    move-result-object p1

    return-object p1
.end method

.method public y()Landroidx/appcompat/view/menu/n40;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/n40$c;->o:Landroidx/appcompat/view/menu/n40;

    return-object v0
.end method
