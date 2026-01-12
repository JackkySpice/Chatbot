.class public Landroidx/appcompat/view/menu/tl$e;
.super Landroidx/appcompat/view/menu/hv;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/tl;->g()Landroidx/appcompat/view/menu/hv;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/hv;

.field public final synthetic b:Landroidx/appcompat/view/menu/tl;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/tl;Landroidx/appcompat/view/menu/hv;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/tl$e;->b:Landroidx/appcompat/view/menu/tl;

    iput-object p2, p0, Landroidx/appcompat/view/menu/tl$e;->a:Landroidx/appcompat/view/menu/hv;

    invoke-direct {p0}, Landroidx/appcompat/view/menu/hv;-><init>()V

    return-void
.end method


# virtual methods
.method public a(I)Landroid/view/View;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tl$e;->a:Landroidx/appcompat/view/menu/hv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/hv;->b()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/tl$e;->a:Landroidx/appcompat/view/menu/hv;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/hv;->a(I)Landroid/view/View;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/tl$e;->b:Landroidx/appcompat/view/menu/tl;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/tl;->m1(I)Landroid/view/View;

    move-result-object p1

    return-object p1
.end method

.method public b()Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tl$e;->a:Landroidx/appcompat/view/menu/hv;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/hv;->b()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tl$e;->b:Landroidx/appcompat/view/menu/tl;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/tl;->n1()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    return v0
.end method
