.class public final Landroidx/appcompat/view/menu/tf$d;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/tf$c;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/tf;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "d"
.end annotation


# instance fields
.field public a:Landroid/content/ClipData;

.field public b:I

.field public c:I

.field public d:Landroid/net/Uri;

.field public e:Landroid/os/Bundle;


# direct methods
.method public constructor <init>(Landroid/content/ClipData;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/tf$d;->a:Landroid/content/ClipData;

    iput p2, p0, Landroidx/appcompat/view/menu/tf$d;->b:I

    return-void
.end method


# virtual methods
.method public a()Landroidx/appcompat/view/menu/tf;
    .locals 2

    new-instance v0, Landroidx/appcompat/view/menu/tf;

    new-instance v1, Landroidx/appcompat/view/menu/tf$g;

    invoke-direct {v1, p0}, Landroidx/appcompat/view/menu/tf$g;-><init>(Landroidx/appcompat/view/menu/tf$d;)V

    invoke-direct {v0, v1}, Landroidx/appcompat/view/menu/tf;-><init>(Landroidx/appcompat/view/menu/tf$f;)V

    return-object v0
.end method

.method public b(Landroid/os/Bundle;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/tf$d;->e:Landroid/os/Bundle;

    return-void
.end method

.method public c(Landroid/net/Uri;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/tf$d;->d:Landroid/net/Uri;

    return-void
.end method

.method public d(I)V
    .locals 0

    iput p1, p0, Landroidx/appcompat/view/menu/tf$d;->c:I

    return-void
.end method
