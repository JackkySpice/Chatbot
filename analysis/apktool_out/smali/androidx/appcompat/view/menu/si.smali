.class public final synthetic Landroidx/appcompat/view/menu/si;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/ti;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:I

.field public final synthetic p:Landroidx/appcompat/view/menu/ti$d;

.field public final synthetic q:Ljava/nio/ByteBuffer;

.field public final synthetic r:J


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ti;Ljava/lang/String;ILandroidx/appcompat/view/menu/ti$d;Ljava/nio/ByteBuffer;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/si;->m:Landroidx/appcompat/view/menu/ti;

    iput-object p2, p0, Landroidx/appcompat/view/menu/si;->n:Ljava/lang/String;

    iput p3, p0, Landroidx/appcompat/view/menu/si;->o:I

    iput-object p4, p0, Landroidx/appcompat/view/menu/si;->p:Landroidx/appcompat/view/menu/ti$d;

    iput-object p5, p0, Landroidx/appcompat/view/menu/si;->q:Ljava/nio/ByteBuffer;

    iput-wide p6, p0, Landroidx/appcompat/view/menu/si;->r:J

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    iget-object v0, p0, Landroidx/appcompat/view/menu/si;->m:Landroidx/appcompat/view/menu/ti;

    iget-object v1, p0, Landroidx/appcompat/view/menu/si;->n:Ljava/lang/String;

    iget v2, p0, Landroidx/appcompat/view/menu/si;->o:I

    iget-object v3, p0, Landroidx/appcompat/view/menu/si;->p:Landroidx/appcompat/view/menu/ti$d;

    iget-object v4, p0, Landroidx/appcompat/view/menu/si;->q:Ljava/nio/ByteBuffer;

    iget-wide v5, p0, Landroidx/appcompat/view/menu/si;->r:J

    invoke-static/range {v0 .. v6}, Landroidx/appcompat/view/menu/ti;->e(Landroidx/appcompat/view/menu/ti;Ljava/lang/String;ILandroidx/appcompat/view/menu/ti$d;Ljava/nio/ByteBuffer;J)V

    return-void
.end method
