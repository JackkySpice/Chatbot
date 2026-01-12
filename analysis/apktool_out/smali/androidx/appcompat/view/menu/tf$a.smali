.class public final Landroidx/appcompat/view/menu/tf$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/tf;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/tf$c;


# direct methods
.method public constructor <init>(Landroid/content/ClipData;I)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1f

    if-lt v0, v1, :cond_0

    new-instance v0, Landroidx/appcompat/view/menu/tf$b;

    invoke-direct {v0, p1, p2}, Landroidx/appcompat/view/menu/tf$b;-><init>(Landroid/content/ClipData;I)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/tf$a;->a:Landroidx/appcompat/view/menu/tf$c;

    goto :goto_0

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/tf$d;

    invoke-direct {v0, p1, p2}, Landroidx/appcompat/view/menu/tf$d;-><init>(Landroid/content/ClipData;I)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/tf$a;->a:Landroidx/appcompat/view/menu/tf$c;

    :goto_0
    return-void
.end method


# virtual methods
.method public a()Landroidx/appcompat/view/menu/tf;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tf$a;->a:Landroidx/appcompat/view/menu/tf$c;

    invoke-interface {v0}, Landroidx/appcompat/view/menu/tf$c;->a()Landroidx/appcompat/view/menu/tf;

    move-result-object v0

    return-object v0
.end method

.method public b(Landroid/os/Bundle;)Landroidx/appcompat/view/menu/tf$a;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tf$a;->a:Landroidx/appcompat/view/menu/tf$c;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/tf$c;->b(Landroid/os/Bundle;)V

    return-object p0
.end method

.method public c(I)Landroidx/appcompat/view/menu/tf$a;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tf$a;->a:Landroidx/appcompat/view/menu/tf$c;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/tf$c;->d(I)V

    return-object p0
.end method

.method public d(Landroid/net/Uri;)Landroidx/appcompat/view/menu/tf$a;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/tf$a;->a:Landroidx/appcompat/view/menu/tf$c;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/tf$c;->c(Landroid/net/Uri;)V

    return-object p0
.end method
