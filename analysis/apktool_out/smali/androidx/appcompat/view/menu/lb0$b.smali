.class public Landroidx/appcompat/view/menu/lb0$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ot0$c;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/lb0;->i()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:F

.field public final synthetic b:Landroidx/appcompat/view/menu/lb0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/lb0;F)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/lb0$b;->b:Landroidx/appcompat/view/menu/lb0;

    iput p2, p0, Landroidx/appcompat/view/menu/lb0$b;->a:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/fh;)Landroidx/appcompat/view/menu/fh;
    .locals 2

    instance-of v0, p1, Landroidx/appcompat/view/menu/io0;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Landroidx/appcompat/view/menu/w1;

    iget v1, p0, Landroidx/appcompat/view/menu/lb0$b;->a:F

    invoke-direct {v0, v1, p1}, Landroidx/appcompat/view/menu/w1;-><init>(FLandroidx/appcompat/view/menu/fh;)V

    move-object p1, v0

    :goto_0
    return-object p1
.end method
